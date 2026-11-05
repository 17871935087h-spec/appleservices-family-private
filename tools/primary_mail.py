import sys
sys.dont_write_bytecode = True

import base64
import ctypes
import hashlib
import http.client
import http.cookies
import json
import os
import re
import secrets
import ssl
import subprocess
import time
import urllib.parse
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

MAX_INPUT = 64 * 1024
MAX_JSON = 2 * 1024 * 1024
MAX_HTTP = 4 * 1024 * 1024
ACCOUNT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
APPLE_ID_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}$")
MAIL_RE = re.compile(r"^[a-zA-Z0-9._+-]+@icloud\.com$", re.I)
ANY_MAIL_RE = re.compile(r"^[a-zA-Z0-9._+-]+@(?:icloud\.com|me\.com|mac\.com)$", re.I)
PREFIX_RE = re.compile(r"^[a-z][a-z0-9._]{2,19}$")
HOST_RE = re.compile(r"^[a-z0-9-]+\.icloud\.com(?:\.cn)?$", re.I)
SETTINGS_HOST = "setup.icloud.com"
SETTINGS_PATH = "/setup/get_account_settings"
MAIL_ENTRY_POINT = "USER_LAUNCH"
CREDENTIAL_HEADER = b"ASCV\x00\x01\x00\x00"
CREDENTIAL_ENTROPY_PREFIX = b"github.com/Laky-64/appleservices/credentialvault/v1\x00"
ALLOWED_STAGES = {
    "unknown", "not_open", "verified", "outcome_unknown",
    "web_login_required", "verification_required", "terms_required",
    "risk_blocked", "unavailable", "busy", "invalid_request",
}
MESSAGES = {
    "unknown": "Apple 主邮箱状态暂不可确认。",
    "not_open": "Apple 原生账户设置确认主邮箱尚未开通。",
    "verified": "Apple 原生账户设置已确认主邮箱。",
    "outcome_unknown": "创建结果尚未确认；系统只执行回读，不会重发创建请求。",
    "web_login_required": "需要先建立本账号的 iCloud Web 会话。",
    "verification_required": "Apple 要求重新验证；当前操作已停止。",
    "terms_required": "Apple 要求先处理条款；当前操作已停止。",
    "risk_blocked": "Apple 账户状态或已有别名阻止了创建。",
    "unavailable": "Apple 主邮箱服务暂不可用。",
    "busy": "该账号的主邮箱操作正在进行。",
    "invalid_request": "请求格式或账号绑定无效。",
}


class Stop(Exception):
    def __init__(self, stage):
        self.stage = stage if stage in ALLOWED_STAGES else "unavailable"


class Context:
    __slots__ = ("account_id", "apple_id", "root", "directory", "dsid", "adsid", "token")

    def __init__(self, account_id, apple_id, root, directory, dsid, adsid, token):
        self.account_id = account_id
        self.apple_id = apple_id
        self.root = root
        self.directory = directory
        self.dsid = dsid
        self.adsid = adsid
        self.token = token

    def __repr__(self):
        return "Context(account_id=%r)" % self.account_id


class Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def checked_d_path(value, must_exist=False):
    if not isinstance(value, str) or not value:
        raise Stop("invalid_request")
    path = Path(value)
    if not path.is_absolute():
        raise Stop("invalid_request")
    try:
        resolved = path.resolve(strict=must_exist)
    except (OSError, RuntimeError):
        raise Stop("unavailable") from None
    if resolved.drive.upper() != "D:":
        raise Stop("invalid_request")
    return resolved


def read_bytes(path, limit=MAX_JSON):
    try:
        if path.is_symlink() or not path.is_file():
            raise Stop("unavailable")
        size = path.stat().st_size
        if size < 0 or size > limit:
            raise Stop("unavailable")
        data = path.read_bytes()
        if len(data) > limit:
            raise Stop("unavailable")
        return data
    except Stop:
        raise
    except OSError:
        raise Stop("unavailable") from None


def read_json(path, limit=MAX_JSON):
    raw = read_bytes(path, limit)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise Stop("unavailable") from None
    if not isinstance(value, dict):
        raise Stop("unavailable")
    return value


def normalized_apple_id(value):
    if not isinstance(value, str):
        return ""
    result = value.strip().casefold()
    return result if APPLE_ID_RE.fullmatch(result) else ""


def resolve_context(request):
    root = checked_d_path(request.get("root"), must_exist=True)
    registry = read_json(root / "accounts.json")
    entries = registry.get("accounts")
    if not isinstance(entries, list):
        raise Stop("invalid_request")
    requested_id = request.get("account_id")
    requested_apple_id = normalized_apple_id(request.get("apple_id"))
    if not isinstance(requested_id, str) or not ACCOUNT_RE.fullmatch(requested_id) or not requested_apple_id:
        raise Stop("invalid_request")

    id_matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("id") == requested_id]
    if len(id_matches) != 1:
        raise Stop("invalid_request")
    entry = id_matches[0]
    registry_apple_id = normalized_apple_id(entry.get("apple_id"))
    if registry_apple_id != requested_apple_id:
        raise Stop("invalid_request")
    if sum(1 for item in entries if isinstance(item, dict) and normalized_apple_id(item.get("apple_id")) == requested_apple_id) != 1:
        raise Stop("invalid_request")

    raw_dir = entry.get("dir")
    if not isinstance(raw_dir, str) or not raw_dir:
        raw_dir = str(root / "accounts" / requested_id)
    directory = checked_d_path(raw_dir, must_exist=True)
    try:
        if not directory.is_relative_to(root) or directory == root:
            raise Stop("invalid_request")
    except AttributeError:
        if os.path.commonpath((str(root), str(directory))) != str(root):
            raise Stop("invalid_request")

    saved = read_json(directory / "session.json")
    accepted = read_json(directory / "icloud-accepted.json")
    accepted_session = accepted.get("session")
    if not isinstance(accepted_session, dict):
        raise Stop("unavailable")
    if normalized_apple_id(saved.get("AppleID")) != requested_apple_id:
        raise Stop("invalid_request")
    if normalized_apple_id(accepted_session.get("AppleID")) != requested_apple_id:
        raise Stop("invalid_request")
    dsid = accepted_session.get("DSID")
    adsid = accepted.get("adsid")
    if not isinstance(dsid, str) or not dsid or not isinstance(adsid, str) or not adsid:
        raise Stop("unavailable")
    if saved.get("DSID") != adsid:
        raise Stop("invalid_request")
    tokens = accepted_session.get("Tokens")
    token = tokens.get("mmeAuthToken") if isinstance(tokens, dict) else None
    if not isinstance(token, str) or not token or not isinstance(accepted.get("service-data"), dict):
        raise Stop("unavailable")
    return Context(requested_id, requested_apple_id, root, directory, dsid, adsid, token)


def credential_entropy(apple_id):
    return hashlib.sha256(CREDENTIAL_ENTROPY_PREFIX + apple_id.casefold().encode("utf-8")).digest()


def _crypt_data(data, protect, entropy):
    if os.name != "nt":
        raise Stop("unavailable")
    source_buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    entropy_buffer = (ctypes.c_ubyte * len(entropy)).from_buffer_copy(entropy)
    source = Blob(len(data), source_buffer)
    salt = Blob(len(entropy), entropy_buffer)
    output = Blob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    function = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    function.argtypes = [
        ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob),
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(Blob),
    ]
    function.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    if not function(ctypes.byref(source), None, ctypes.byref(salt), None, None, 1, ctypes.byref(output)):
        raise Stop("unavailable")
    try:
        if not output.pbData or output.cbData > 8 * 1024 * 1024:
            raise Stop("unavailable")
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        if output.pbData:
            kernel32.LocalFree(ctypes.cast(output.pbData, ctypes.c_void_p))


def credential_blob(raw):
    if len(raw) < 12 or raw[:8] != CREDENTIAL_HEADER:
        raise Stop("unavailable")
    size = int.from_bytes(raw[8:12], "big")
    if size <= 0 or size > 128 * 1024 or size != len(raw) - 12:
        raise Stop("unavailable")
    return raw[12:]


def load_password(context):
    raw = bytearray(read_bytes(context.directory / "credential.dpapi", 1 << 20))
    try:
        ciphertext = credential_blob(raw)
        plain = bytearray(_crypt_data(bytes(ciphertext), False, credential_entropy(context.apple_id)))
        try:
            if not plain or len(plain) > 1024:
                raise Stop("unavailable")
            password = plain.decode("utf-8")
            if not password.strip() or any(char in password for char in ("\x00", "\r", "\n")):
                raise Stop("unavailable")
            return password, plain
        except UnicodeError:
            for index in range(len(plain)):
                plain[index] = 0
            raise Stop("unavailable") from None
    finally:
        for index in range(len(raw)):
            raw[index] = 0


def _safe_file_path(path):
    if path.is_symlink():
        raise Stop("unavailable")
    return path


def _fsync_directory(path):
    if os.name == "nt":
        return
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def write_exclusive(path, data):
    _safe_file_path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError:
        raise Stop("outcome_unknown") from None
    except OSError:
        raise Stop("unavailable") from None
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise Stop("unavailable") from None
    _fsync_directory(path.parent)


def write_exclusive_json(path, value):
    data = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    write_exclusive(path, data)


def write_atomic_json(path, value):
    _safe_file_path(path)
    pending = path.with_name(path.name + "." + secrets.token_hex(8) + ".pending")
    data = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(str(pending), flags, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if path.exists() and path.is_symlink():
            raise Stop("unavailable")
        os.replace(str(pending), str(path))
        _fsync_directory(path.parent)
    except Stop:
        try:
            pending.unlink()
        except OSError:
            pass
        raise
    except OSError:
        try:
            pending.unlink()
        except OSError:
            pass
        raise Stop("unavailable") from None


def write_exclusive_bytes(path, data):
    write_exclusive(path, data)


@contextmanager
def account_lock(directory):
    lock_path = directory / "operation.lock"
    _safe_file_path(lock_path)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(str(lock_path), flags, 0o600)
    except OSError:
        raise Stop("unavailable") from None
    locked = False
    try:
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
            os.fsync(fd)
        if os.name == "nt":
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError:
                raise Stop("busy") from None
            locked = True
        else:
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise Stop("busy") from None
            locked = True
        yield
    finally:
        if locked:
            try:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def native_headers(context, request):
    helper = checked_d_path(request.get("native_helper"), must_exist=True)
    library = checked_d_path(request.get("library"), must_exist=True)
    python = checked_d_path(request.get("python"), must_exist=True)
    args = [
        str(helper), "-account-dir", str(context.directory),
        "-adi-dll", str(library), "-python", str(python),
    ]
    allowed = {
        "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC",
        "PATHEXT", "SYSTEMDRIVE", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    }
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    mail_dir = context.directory / "primary-mail"
    temp_dir = mail_dir / "tmp"
    if mail_dir.is_symlink() or temp_dir.is_symlink():
        raise Stop("invalid_request")
    resolved_temp = checked_d_path(str(temp_dir))
    if not resolved_temp.is_relative_to(context.directory):
        raise Stop("invalid_request")
    temp_dir.mkdir(parents=True, exist_ok=True)
    if temp_dir.is_symlink() or not temp_dir.is_dir():
        raise Stop("invalid_request")
    env["TEMP"] = env["TMP"] = str(temp_dir)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        completed = subprocess.run(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=60, env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Stop("unavailable") from None
    if completed.returncode != 0 or len(completed.stdout) > 65536:
        raise Stop("unavailable")
    try:
        headers = json.loads(completed.stdout)
    except (ValueError, UnicodeError):
        raise Stop("unavailable") from None
    if not isinstance(headers, dict):
        raise Stop("unavailable")
    for key, value in headers.items():
        if (not isinstance(key, str) or not isinstance(value, str)
                or not re.fullmatch(r"[A-Za-z0-9-]+", key)
                or "\r" in value or "\n" in value
                or not (key.lower().startswith("x-") or key.lower() == "user-agent")):
            raise Stop("unavailable")
    if not all(headers.get(key) for key in ("X-Mme-Device-Id", "X-Apple-I-MD", "X-Apple-I-MD-M")):
        raise Stop("unavailable")
    return headers


class NativeTransport:
    def __init__(self, context, headers):
        self.context = context
        self.headers = dict(headers)

    def request(self, method, path, body, headers):
        if path != SETTINGS_PATH or method not in {"GET", "POST"}:
            raise Stop("unavailable")
        request_headers = dict(headers)
        auth = base64.b64encode((self.context.dsid + ":" + self.context.token).encode("utf-8")).decode("ascii")
        request_headers["Authorization"] = "Basic " + auth
        conn = http.client.HTTPSConnection(SETTINGS_HOST, timeout=15, context=ssl.create_default_context())
        try:
            conn.request(method, path, body=body, headers=request_headers)
            response = conn.getresponse()
            raw = response.read(MAX_JSON + 1)
            if len(raw) > MAX_JSON:
                raise Stop("unavailable")
            return NativeReply(response.status, raw)
        except Stop:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError):
            raise Stop("unavailable") from None
        finally:
            conn.close()

    def settings(self):
        headers = dict(self.headers)
        headers.update({
            "X-Apple-ADSID": self.context.adsid,
            "X-MMe-Country": "US",
            "X-MMe-Language": "en",
            "Accept": "application/x-plist",
            "Cookie": "termsAccepted=true",
            "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
        })
        headers.setdefault("X-Mme-Client-Info", "<MacBook Pro> <Mac OS X;10.10;14A314h> <com.apple.AOSKit/203>")
        reply = self.request("POST", SETTINGS_PATH, b"", headers)
        if reply.status == 409:
            reply = self.request("GET", SETTINGS_PATH, None, headers)
        return reply


class NativeReply:
    __slots__ = ("status", "body")

    def __init__(self, status, body):
        self.status, self.body = status, body


def decode_settings(body):
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError):
        try:
            import plistlib
            value = plistlib.loads(body)
        except Exception:
            return None
    return value if isinstance(value, dict) else None


def safe_settings(reply, expected_dsid):
    result = {
        "http_status": reply.status, "parsed": False, "account_info_present": False,
        "primary_field_present": False, "primary_field_empty": False,
        "primary_state": "unknown", "primary_address": None,
        "response_identity": "absent", "apple_mail_aliases": [],
        "business_error": None, "account_locked": None,
    }
    doc = decode_settings(reply.body)
    if doc is None:
        return result
    result["parsed"] = True
    result["business_error"] = bool(doc.get("ErrorID"))
    for key in ("errorCode", "statusCode"):
        if key in doc and not (
            type(doc[key]) is int and doc[key] == 0
            or isinstance(doc[key], str) and doc[key] in {"", "0", "OK", "SUCCESS"}
        ):
            result["business_error"] = True
    service = doc.get("com.apple.mobileme")
    candidates = []
    if isinstance(doc.get("appleAccountInfo"), dict):
        candidates.append(doc["appleAccountInfo"])
    if isinstance(service, dict) and isinstance(service.get("appleAccountInfo"), dict):
        candidates.append(service["appleAccountInfo"])
    if len(candidates) != 1 or reply.status != 200:
        return result
    info = candidates[0]
    result["account_info_present"] = True
    result["account_locked"] = info.get("locked") if type(info.get("locked")) is bool else None
    identity = info.get("dsPrsID")
    if expected_dsid is not None and type(identity) in (str, int):
        result["response_identity"] = "matched" if str(identity) == expected_dsid else "mismatch"
    result["primary_field_present"] = "iCloudAppleIdAlias" in info
    direct = info.get("iCloudAppleIdAlias")
    result["primary_field_empty"] = isinstance(direct, str) and not direct.strip()
    if result["primary_field_empty"]:
        result["primary_state"] = "empty"
    unsupported_mail = False
    if isinstance(direct, str) and ANY_MAIL_RE.fullmatch(direct.strip()):
        if MAIL_RE.fullmatch(direct.strip()):
            result["primary_state"] = "present"
            result["primary_address"] = direct.strip().casefold()
        else:
            result["primary_state"] = "unsupported"
            unsupported_mail = True
    aliases = [direct]
    if isinstance(info.get("appleIdAliases"), list):
        aliases += info["appleIdAliases"]
    for value in aliases:
        if isinstance(value, str) and ANY_MAIL_RE.fullmatch(value.strip()):
            address = value.strip().casefold()
            if MAIL_RE.fullmatch(value.strip()) and address not in result["apple_mail_aliases"]:
                result["apple_mail_aliases"].append(address)
            elif not MAIL_RE.fullmatch(value.strip()):
                unsupported_mail = True
    result["unsupported_mail"] = unsupported_mail
    if result["primary_state"] == "empty" and (result["apple_mail_aliases"] or unsupported_mail):
        result["primary_state"] = "existing_aliases"
    return result


def read_native_settings(context, request):
    headers = native_headers(context, request)
    return safe_settings(NativeTransport(context, headers).settings(), context.dsid)


def stage_from_native(settings):
    if settings.get("account_locked") is True:
        return "risk_blocked"
    if settings.get("unsupported_mail") is True or settings.get("primary_state") == "unsupported":
        return "unavailable"
    if settings.get("http_status") in (401, 403, 429):
        return "risk_blocked"
    if (settings.get("http_status") != 200 or settings.get("parsed") is not True
            or settings.get("account_info_present") is not True
            or settings.get("response_identity") != "matched"
            or settings.get("business_error") is not False):
        return "unknown"
    if settings.get("account_locked") is not False:
        return "unknown"
    if settings.get("primary_state") == "present" and isinstance(settings.get("primary_address"), str):
        return "verified"
    if (settings.get("primary_state") == "empty"
            and settings.get("primary_field_present") is True
            and settings.get("apple_mail_aliases") == []):
        return "not_open"
    if settings.get("primary_state") == "existing_aliases" or settings.get("apple_mail_aliases"):
        return "risk_blocked"
    return "unknown"


def exact_primary_match(settings, target):
    return (
        settings.get("http_status") == 200
        and settings.get("account_info_present") is True
        and settings.get("response_identity") == "matched"
        and settings.get("business_error") is False
        and settings.get("account_locked") is False
        and settings.get("primary_state") == "present"
        and settings.get("primary_address") == target
    )


def cookie_header(cookies, url):
    target = urllib.parse.urlsplit(url)
    pairs = []
    for cookie in cookies:
        if not isinstance(cookie, dict):
            raise Stop("unavailable")
        domain = cookie.get("domain", "").lower().lstrip(".")
        host = (target.hostname or "").lower()
        match = host == domain or (cookie.get("host_only") is not True and host.endswith("." + domain))
        path = cookie.get("path", "/") or "/"
        request_path = target.path or "/"
        path_match = (
            request_path == path
            or request_path.startswith(path) and (path.endswith("/") or request_path[len(path):].startswith("/"))
        )
        expiry = cookie.get("expires", 0)
        name, value = cookie.get("name", ""), cookie.get("value", "")
        if not match or not path_match or (expiry and expiry <= time.time()) or (cookie.get("secure") and target.scheme != "https"):
            continue
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", name)
                or not isinstance(value, str) or any(char in value for char in "\r\n;")):
            raise Stop("unavailable")
        pairs.append((len(path), name + "=" + value))
    return "; ".join(value for _, value in sorted(pairs, key=lambda row: -row[0]))


class WebClient:
    def __init__(self, session, record):
        self.session = session
        self.record = record
        self.calls = set()
        self.gateway = ""
        states = [
            item for item in session.get("login_states", [])
            if isinstance(item, dict) and item.get("kind") == "icloud_web" and item.get("last_check_ok") is True
        ] if isinstance(session.get("login_states"), list) else []
        if len(states) != 1 or not isinstance(states[0].get("cookies"), list) or not states[0]["cookies"]:
            raise Stop("unavailable")
        self.cookies = list(states[0]["cookies"])
        self.agent = states[0].get("user_agent") or "Mozilla/5.0"
        self.host = session.get("host")
        if self.host not in ("www.icloud.com", "www.icloud.com.cn"):
            raise Stop("unavailable")
        self.setup_host = "setup.icloud.com.cn" if self.host.endswith(".cn") else "setup.icloud.com"

    def request(self, method, url, payload=None):
        target = urllib.parse.urlsplit(url)
        if (target.scheme != "https" or target.username or target.password
                or target.port not in (None, 443) or target.fragment):
            raise Stop("unavailable")
        validate_path = "/setup/ws/1/validate"
        is_validate = (
            target.hostname == self.setup_host and target.path == validate_path and method == "POST"
        )
        gateway = urllib.parse.urlsplit(self.gateway) if self.gateway else None
        mail_paths = {"/mailacct/v1/web/emailAvailability", "/mailacct/v1/web/activateEmail"}
        is_mail = (
            gateway is not None and target.hostname == gateway.hostname
            and target.port in (None, 443) and method == "POST"
            and target.path in {gateway.path.rstrip("/") + suffix for suffix in mail_paths}
        )
        if not (is_validate or is_mail):
            raise Stop("risk_blocked")
        if target.path.endswith("/activateEmail") and (
            self.record.get("stage") != "intent" or self.record.get("activation_attempts") != 1
        ):
            raise Stop("outcome_unknown")
        query = urllib.parse.parse_qsl(target.query, keep_blank_values=True)
        if is_mail:
            current = dict(query)
            current.update({
                "clientBuildNumber": self.session.get("client_build_number") or "2622Build20",
                "clientMasteringNumber": self.session.get("mastering_number") or "2622Build20",
                "clientId": self.session["client_id"],
                "dsid": self.session["dsid"],
            })
            query = list(current.items())
        full_url = urllib.parse.urlunsplit((target.scheme, target.netloc, target.path, urllib.parse.urlencode(query), ""))
        key = method + " " + target.path
        if key in self.calls and not (
            is_validate and self.record.get("activation_attempts") == 1
            and self.record.get("web_after") is None
        ):
            raise Stop("outcome_unknown")
        self.calls.add(key)
        cookie = cookie_header(self.cookies, full_url)
        if not cookie:
            raise Stop("unavailable")
        headers = {
            "Cookie": cookie, "Origin": "https://" + self.host, "Referer": "https://" + self.host + "/",
            "User-Agent": self.agent, "Accept": "application/json", "Content-Type": "application/json",
            "Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
        }
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        try:
            connection = http.client.HTTPSConnection(
                target.hostname, timeout=25, context=ssl.create_default_context()
            )
            try:
                parsed_full = urllib.parse.urlsplit(full_url)
                path = target.path + (("?" + parsed_full.query) if parsed_full.query else "")
                connection.request(method, path, body=body, headers=headers)
                response = connection.getresponse()
                raw = response.read(MAX_HTTP + 1)
                if len(raw) > MAX_HTTP:
                    raise Stop("unavailable")
                try:
                    document = json.loads(raw)
                except (ValueError, UnicodeError):
                    raise Stop("unavailable") from None
                if not isinstance(document, dict):
                    raise Stop("unavailable")
                if response.status in (401, 403, 429):
                    raise Stop("risk_blocked")
                error = document.get("errorCode")
                if response.status < 200 or response.status >= 300 or document.get("success") is False or error not in (None, "", 0, "0"):
                    raise Stop("unavailable")
                self._update_cookies(response.headers.get_all("Set-Cookie", []), target.hostname, target.path)
                return document
            finally:
                connection.close()
        except Stop:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError, TimeoutError):
            raise Stop("unavailable") from None

    def _update_cookies(self, headers, host, request_path):
        for header in headers:
            incoming = http.cookies.SimpleCookie()
            try:
                incoming.load(header)
            except Exception:
                continue
            for name, morsel in incoming.items():
                domain = (morsel["domain"] or host).lstrip(".").lower()
                if host != domain and not host.endswith("." + domain):
                    continue
                path = morsel["path"] or request_path.rsplit("/", 1)[0] + "/"
                if not path.startswith("/") or "\r" in path or "\n" in path:
                    continue
                identity = (name, domain, path)
                self.cookies = [
                    item for item in self.cookies
                    if (item.get("name"), item.get("domain", "").lstrip(".").lower(), item.get("path")) != identity
                ]
                expiry = 0
                max_age = morsel["max-age"]
                if re.fullmatch(r"-?[0-9]+", max_age or ""):
                    expiry = time.time() + int(max_age)
                elif morsel["expires"]:
                    try:
                        from email.utils import parsedate_to_datetime
                        expiry = parsedate_to_datetime(morsel["expires"]).timestamp()
                    except (TypeError, ValueError, OverflowError):
                        continue
                if expiry and expiry <= time.time():
                    continue
                self.cookies.append({
                    "name": name, "value": morsel.value, "domain": domain, "path": path,
                    "host_only": not bool(morsel["domain"]), "secure": bool(morsel["secure"]),
                    "expires": expiry,
                })

    def validate(self, expected_apple_id, expected_dsid, target):
        query = urllib.parse.urlencode({
            "clientBuildNumber": self.session.get("client_build_number") or "2622Build20",
            "clientMasteringNumber": self.session.get("mastering_number") or "2622Build20",
            "clientId": self.session["client_id"], "requestId": str(uuid.uuid4()),
        })
        value = self.request("POST", "https://" + self.setup_host + "/setup/ws/1/validate?" + query)
        if value.get("termsUpdateNeeded"):
            raise Stop("terms_required")
        if value.get("hsaChallengeRequired") or value.get("hsaTrustedBrowser") is False:
            raise Stop("verification_required")
        info = value.get("dsInfo")
        if not isinstance(info, dict):
            raise Stop("unavailable")
        if (str(info.get("dsid", "")) != expected_dsid
                or not isinstance(info.get("appleId"), str)
                or info["appleId"].casefold() != expected_apple_id.casefold()):
            raise Stop("risk_blocked")
        services = value.get("webservices")
        if not isinstance(services, dict):
            raise Stop("unavailable")
        mail_gateway = services.get("mccgateway")
        gateway = mail_gateway.get("url") if isinstance(mail_gateway, dict) else None
        parsed = urllib.parse.urlsplit(gateway or "")
        if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443)
                or not HOST_RE.fullmatch(parsed.hostname or "") or parsed.query or parsed.fragment):
            raise Stop("unavailable")
        self.gateway = gateway.rstrip("/")
        flags = value.get("mailFlags", info.get("mailFlags", {}))
        mail_flag = flags.get("isCKMail") if isinstance(flags, dict) and type(flags.get("isCKMail")) is bool else None
        mail_service = services.get("mail")
        return {
            "mail_service_present": bool(mail_service.get("url")) if isinstance(mail_service, dict) else False,
            "mail_flag": mail_flag,
            "primary_email_matches_target": (
                isinstance(info.get("primaryEmail"), str)
                and info["primaryEmail"].casefold() == target.casefold()
            ),
        }

    def availability(self, target):
        value = self.request(
            "POST", self.gateway + "/mailacct/v1/web/emailAvailability",
            {"email": target, "entryPoint": MAIL_ENTRY_POINT},
        )
        if value.get("email") != target or value.get("available") is not True:
            raise Stop("unavailable")

    def activate(self, target):
        return self.request(
            "POST", self.gateway + "/mailacct/v1/web/activateEmail",
            {"email": target, "patternId": "", "entryPoint": MAIL_ENTRY_POINT},
        )


def make_target(prefix):
    if not isinstance(prefix, str):
        raise Stop("invalid_request")
    value = prefix.strip()
    if not value:
        value = "mail" + secrets.token_hex(5)
    if not PREFIX_RE.fullmatch(value) or ".." in value:
        raise Stop("invalid_request")
    return value + "@icloud.com"


def target_from_record(path):
    try:
        record = read_json(path, 64 * 1024)
    except Stop:
        return ""
    target = record.get("target")
    return target.casefold() if isinstance(target, str) and MAIL_RE.fullmatch(target) else ""


def current_primary_reply(account_id, native, can_create=False, target=""):
    stage = stage_from_native(native)
    email = native.get("primary_address") if stage == "verified" else None
    return make_reply(account_id, stage, email=email, target=target, can_create=(can_create and stage == "not_open"))


def make_reply(account_id, stage, email=None, target=None, can_create=False):
    stage = stage if stage in ALLOWED_STAGES else "unavailable"
    result = {
        "account_id": account_id if isinstance(account_id, str) and ACCOUNT_RE.fullmatch(account_id) else "",
        "stage": stage, "message": MESSAGES[stage], "can_create": bool(can_create),
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if isinstance(email, str) and MAIL_RE.fullmatch(email):
        result["email"] = email.casefold()
    if isinstance(target, str) and MAIL_RE.fullmatch(target):
        result["target"] = target.casefold()
    return result


def read_legacy_history(directory):
    paths = (
        directory / "primary-mail-once" / "operation.json",
        directory / "mail-mccgateway-once" / "operation.json",
    )
    return any(path.exists() or path.is_symlink() for path in paths)


def session_path(directory):
    return directory / "primary-mail" / "session.dpapi"


def validate_session(session, context):
    if not isinstance(session, dict):
        raise Stop("unavailable")
    if normalized_apple_id(session.get("apple_id")) != context.apple_id:
        raise Stop("risk_blocked")
    if session.get("dsid") != context.dsid:
        raise Stop("risk_blocked")
    if session.get("host") not in ("www.icloud.com", "www.icloud.com.cn"):
        raise Stop("unavailable")
    states = session.get("login_states")
    if not isinstance(states, list):
        raise Stop("unavailable")
    web_states = [
        item for item in states
        if isinstance(item, dict) and item.get("kind") == "icloud_web"
        and item.get("last_check_ok") is True and isinstance(item.get("cookies"), list)
        and item.get("cookies")
    ]
    if len(web_states) != 1 or not isinstance(session.get("client_id"), str) or not session["client_id"]:
        raise Stop("unavailable")
    return session


def read_saved_web_session(context):
    path = session_path(context.directory)
    if path.is_symlink():
        raise Stop("unavailable")
    if not path.exists():
        return None
    raw = bytearray(read_bytes(path, 8 * 1024 * 1024))
    try:
        plain = bytearray(_crypt_data(bytes(raw), False, credential_entropy(context.apple_id)))
    finally:
        for index in range(len(raw)):
            raw[index] = 0
    try:
        session = json.loads(plain)
        return validate_session(session, context)
    except (ValueError, UnicodeError):
        raise Stop("unavailable") from None
    finally:
        for index in range(len(plain)):
            plain[index] = 0


def store_web_session(context, session):
    session = validate_session(session, context)
    raw = bytearray(json.dumps(session, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
    protected = bytearray()
    try:
        protected = bytearray(_crypt_data(bytes(raw), True, credential_entropy(context.apple_id)))
        target = session_path(context.directory)
        target.parent.mkdir(parents=True, exist_ok=True)
        write_exclusive_bytes(target, protected)
    finally:
        for value in (raw, protected):
            for index in range(len(value)):
                value[index] = 0


def helper_environment(temp_dir):
    allowed = {
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE",
        "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    }
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    env["TEMP"] = env["TMP"] = str(temp_dir)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def login_failure_stage(code):
    if not isinstance(code, str):
        return "unavailable"
    value = code.casefold()
    if "terms" in value:
        return "terms_required"
    if any(term in value for term in ("2fa", "verification", "trusted_device", "security_code", "challenge")):
        return "verification_required"
    if any(term in value for term in ("risk", "locked", "too_many", "rate_limit")):
        return "risk_blocked"
    if re.search(r"(?:^|_)(?:401|403|429)(?:_|$)", value):
        return "risk_blocked"
    return "unavailable"


def run_login_helper(context, request, password):
    helper = checked_d_path(request.get("login_helper"), must_exist=True)
    dashboard = request.get("dashboard_url")
    parsed = urllib.parse.urlsplit(dashboard if isinstance(dashboard, str) else "")
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port != 18741
            or parsed.username or parsed.password or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        raise Stop("invalid_request")
    host = "www.icloud.com.cn"
    payload = bytearray(json.dumps({
        "account_id": context.account_id, "apple_id": context.apple_id,
        "password": password, "expected_dsid": context.dsid, "host": host,
        "dashboard_url": "http://127.0.0.1:18741",
    }, separators=(",", ":")).encode("utf-8") + b"\n")
    temp_dir = context.directory / "primary-mail" / "tmp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            [str(helper)], input=bytes(payload), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=125, env=helper_environment(temp_dir),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False,
        )
    except subprocess.TimeoutExpired:
        raise Stop("outcome_unknown") from None
    except OSError:
        raise Stop("unavailable") from None
    finally:
        for index in range(len(payload)):
            payload[index] = 0
    if len(completed.stdout) > 8 * 1024 * 1024 or len(completed.stdout.splitlines()) != 1:
        raise Stop("outcome_unknown")
    try:
        result = json.loads(completed.stdout)
    except (ValueError, UnicodeError):
        raise Stop("outcome_unknown") from None
    if not isinstance(result, dict):
        raise Stop("outcome_unknown")
    if result.get("stage") != "authenticated" or completed.returncode != 0:
        raise Stop(login_failure_stage(result.get("code")))
    session = validate_session(result.get("session"), context)
    if session.get("host") != host:
        raise Stop("risk_blocked")
    return session


def load_or_login_web_session(context, request):
    saved = read_saved_web_session(context)
    if saved is not None:
        return saved
    mail_dir = context.directory / "primary-mail"
    intent_path = mail_dir / "login-intent.json"
    state_path = mail_dir / "login-state.json"
    if intent_path.exists() or intent_path.is_symlink():
        try:
            state = read_json(state_path, 64 * 1024)
            stage = state.get("stage")
            if stage in {"verification_required", "terms_required", "risk_blocked", "unavailable"}:
                raise Stop(stage)
        except Stop as exc:
            if exc.stage != "unavailable":
                raise
        raise Stop("outcome_unknown")
    if request.get("allow_web_login") is not True:
        raise Stop("web_login_required")
    mail_dir.mkdir(parents=True, exist_ok=True)
    password, password_bytes = load_password(context)
    try:
        write_exclusive_json(intent_path, {
            "account_id": context.account_id, "stage": "intent",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        session = run_login_helper(context, request, password)
        store_web_session(context, session)
        write_atomic_json(state_path, {
            "account_id": context.account_id, "stage": "verified",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        return session
    except Stop as exc:
        try:
            write_atomic_json(state_path, {
                "account_id": context.account_id, "stage": exc.stage,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
        except Stop:
            pass
        raise
    finally:
        password = ""
        for index in range(len(password_bytes)):
            password_bytes[index] = 0


class Services:
    def native_read(self, context, request):
        return read_native_settings(context, request)

    def web_session(self, context, request):
        return load_or_login_web_session(context, request)

    def web_client(self, session, record):
        return WebClient(session, record)

    def now(self):
        return datetime.now(timezone.utc).isoformat()


def perform_create(context, request, native_before, services):
    state = stage_from_native(native_before)
    if state == "verified":
        return current_primary_reply(context.account_id, native_before, False)
    mail_dir = context.directory / "primary-mail"
    operation_path = mail_dir / "operation.json"
    operation_exists = operation_path.exists() or operation_path.is_symlink()
    prior_target = target_from_record(operation_path) if operation_exists else ""
    if operation_exists:
        return make_reply(context.account_id, "outcome_unknown", target=prior_target, can_create=False)
    if read_legacy_history(context.directory):
        return make_reply(context.account_id, "outcome_unknown", can_create=False)
    if state != "not_open":
        return current_primary_reply(context.account_id, native_before, False)
    if native_before.get("account_locked") is not False:
        return make_reply(context.account_id, "unknown", can_create=False)

    target = make_target(request.get("prefix", ""))
    try:
        session = services.web_session(context, request)
    except Stop as exc:
        can_create = exc.stage in {"web_login_required", "verification_required", "terms_required"}
        return make_reply(context.account_id, exc.stage, target=target, can_create=can_create)

    record = {
        "account_id": context.account_id, "stage": "preflight", "target": target,
        "activation_attempts": 0, "created_at": services.now(),
    }
    try:
        client = services.web_client(session, record)
        web_before = client.validate(context.apple_id, context.dsid, target)
        if web_before.get("primary_email_matches_target"):
            return make_reply(context.account_id, "risk_blocked", target=target, can_create=False)
        if web_before.get("mail_flag") is True and web_before.get("mail_service_present") is True:
            return make_reply(context.account_id, "risk_blocked", target=target, can_create=False)
        client.availability(target)
    except Stop as exc:
        can_create = exc.stage in {"web_login_required", "verification_required", "terms_required"}
        return make_reply(context.account_id, exc.stage, target=target, can_create=can_create)
    except Exception:
        return make_reply(context.account_id, "unavailable", target=target, can_create=False)

    mail_dir.mkdir(parents=True, exist_ok=True)
    record.update(stage="intent", activation_attempts=1, availability_confirmed=True)
    try:
        write_exclusive_json(operation_path, record)
    except Stop:
        current = services.native_read(context, request)
        if stage_from_native(current) == "verified":
            return current_primary_reply(context.account_id, current, False, target)
        return make_reply(context.account_id, "outcome_unknown", target=target, can_create=False)

    try:
        activation = client.activate(target)
        record["activation_reply_matches_target"] = activation.get("email") == target
        record["web_after"] = None
        web_after = client.validate(context.apple_id, context.dsid, target)
        record["web_after"] = {
            "mail_flag": web_after.get("mail_flag") is True,
            "mail_service_present": web_after.get("mail_service_present") is True,
        }
        native_after = services.native_read(context, request)
        confirmed = (
            record["activation_reply_matches_target"] is True
            and web_after.get("mail_flag") is True
            and web_after.get("mail_service_present") is True
            and exact_primary_match(native_after, target)
        )
        record["stage"] = "verified" if confirmed else "outcome_unknown"
        record["native_readback_matches_target"] = exact_primary_match(native_after, target)
        write_atomic_json(operation_path, record)
        if confirmed:
            return make_reply(context.account_id, "verified", email=target, target=target, can_create=False)
        return make_reply(context.account_id, "outcome_unknown", target=target, can_create=False)
    except Stop:
        record["stage"] = "outcome_unknown"
        try:
            write_atomic_json(operation_path, record)
        except Stop:
            pass
        return make_reply(context.account_id, "outcome_unknown", target=target, can_create=False)
    except Exception:
        record["stage"] = "outcome_unknown"
        try:
            write_atomic_json(operation_path, record)
        except Stop:
            pass
        return make_reply(context.account_id, "outcome_unknown", target=target, can_create=False)


def run_request(request, services=None):
    if not isinstance(request, dict):
        return make_reply("", "invalid_request")
    allowed = {
        "action", "root", "account_id", "apple_id", "prefix", "allow_web_login",
        "confirm_permanent", "library", "python", "login_helper", "native_helper",
        "dashboard_url",
    }
    if set(request) - allowed:
        return make_reply(request.get("account_id", ""), "invalid_request")
    if type(request.get("allow_web_login", False)) is not bool or type(request.get("confirm_permanent", False)) is not bool:
        return make_reply(request.get("account_id", ""), "invalid_request")
    if not isinstance(request.get("action"), str) or request["action"] not in {"status", "create"}:
        return make_reply(request.get("account_id", ""), "invalid_request")
    try:
        context = resolve_context(request)
    except Stop as exc:
        return make_reply(request.get("account_id", ""), exc.stage)

    services = services or Services()
    try:
        if request["action"] == "status":
            native = services.native_read(context, request)
            stage = stage_from_native(native)
            if stage == "verified":
                return current_primary_reply(context.account_id, native, False)
            mail_dir = context.directory / "primary-mail"
            operation = mail_dir / "operation.json"
            if operation.exists() or operation.is_symlink() or read_legacy_history(context.directory):
                return make_reply(context.account_id, "outcome_unknown", target=target_from_record(operation))
            if stage != "not_open":
                return current_primary_reply(context.account_id, native, False)
            login_intent = mail_dir / "login-intent.json"
            login_state = mail_dir / "login-state.json"
            saved_session = session_path(context.directory)
            if login_intent.exists() or login_intent.is_symlink():
                if saved_session.exists() and not saved_session.is_symlink():
                    return current_primary_reply(context.account_id, native, True)
                try:
                    previous = read_json(login_state, 64 * 1024)
                    previous_stage = previous.get("stage")
                except Stop:
                    previous_stage = "outcome_unknown"
                if previous_stage not in {"verification_required", "terms_required", "risk_blocked", "unavailable"}:
                    previous_stage = "outcome_unknown"
                return make_reply(context.account_id, previous_stage)
            return current_primary_reply(context.account_id, native, True)
        if request.get("confirm_permanent") is not True:
            return make_reply(context.account_id, "invalid_request")
        mail_dir = context.directory / "primary-mail"
        if mail_dir.is_symlink():
            return make_reply(context.account_id, "invalid_request")
        try:
            mail_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return make_reply(context.account_id, "unavailable")
        if not mail_dir.is_dir():
            return make_reply(context.account_id, "invalid_request")
        try:
            with account_lock(mail_dir):
                try:
                    native = services.native_read(context, request)
                except Stop as exc:
                    return make_reply(context.account_id, exc.stage)
                return perform_create(context, request, native, services)
        except Stop as exc:
            return make_reply(context.account_id, exc.stage)
    except Stop as exc:
        return make_reply(context.account_id, exc.stage)
    except Exception:
        return make_reply(context.account_id, "unavailable")


def main():
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        result = make_reply("", "invalid_request")
    else:
        try:
            request = json.loads(raw)
        except (ValueError, UnicodeError):
            request = {}
            result = make_reply("", "invalid_request")
        else:
            result = run_request(request)
    sys.stdout.write(json.dumps(result, separators=(",", ":"), ensure_ascii=True) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
