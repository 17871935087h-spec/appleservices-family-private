"""Direct HTTPS transport for the purchase skill; payloads stay on private pipes."""
import base64
import json
import os
from pathlib import Path
import plistlib
import re
import sys
from html import escape
from urllib.parse import urlsplit

import requests


PROXY_MARKER = Path(__file__).resolve().parents[1] / ".cache" / "store-proxy-10808.enabled"
ACCOUNT_PROXY_ENV = "APPLESERVICES_ACCOUNT_PROXY"
ACCOUNT_PROXY_SCHEMES = {"http", "https", "socks5", "socks5h"}


def account_proxy_url():
    value = os.environ.get(ACCOUNT_PROXY_ENV)
    if value is None or value == "":
        if os.environ.get("APPLESERVICES_PROXY_POOL"):
            raise ValueError("account proxy missing for configured pool")
        return None
    if (value != value.strip() or len(value) > 4096
            or any(ord(char) < 0x21 or ord(char) == 0x7f for char in value)):
        raise ValueError("invalid account proxy configuration")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("invalid account proxy configuration") from None
    if (parsed.scheme.lower() not in ACCOUNT_PROXY_SCHEMES or not parsed.hostname
            or port == 0 or (port is not None and not 1 <= port <= 65535)
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or (parsed.username is not None and (not parsed.username or parsed.password is None))):
        raise ValueError("invalid account proxy configuration")
    return value


def configure_transport(session):
    session.trust_env = False
    session.verify = True
    proxy = account_proxy_url()
    if proxy is not None:
        # A configured account proxy takes precedence over the legacy local
        # marker. Explicit proxies are applied to every remote request made by
        # this helper, including the Store bag lookup; failures are fatal.
        session.proxies.update({"http": proxy, "https": proxy})
    elif PROXY_MARKER.is_file():
        local_proxy = "http://127.0.0.1:10808"
        session.proxies.update({"http": local_proxy, "https": local_proxy})


def main():
    message = json.load(sys.stdin)
    endpoint = urlsplit(message["url"])
    allowed = endpoint.hostname in {
        "init.itunes.apple.com", "auth.itunes.apple.com",
        "buy.itunes.apple.com", "speedysub.itunes.apple.com"
    } or re.fullmatch(r"p[0-9]+-buy\.itunes\.apple\.com", endpoint.hostname or "")
    if endpoint.scheme != "https" or not allowed or endpoint.username or endpoint.fragment:
        raise ValueError("unsupported endpoint")
    headers = message["headers"]
    headers.pop("Content-Length", None)
    headers.pop("Accept-Encoding", None)
    data = base64.b64decode(message["body"] or "")
    # Apple's native Store edge is sensitive to the historical Configurator
    # XML shape. Preserve the six fields and their known order instead of the
    # map order emitted by a generic plist encoder.
    request_url = message["url"]
    if endpoint.hostname == "auth.itunes.apple.com" and endpoint.path.rstrip("/") == "/auth/v1/native/fast":
        values = plistlib.loads(data)
        keys = ("appleId", "attempt", "guid", "password", "rmp", "why")
        if set(values) != set(keys):
            raise ValueError("unexpected Store login fields")
        items = "\n".join(
            f"<key>{key}</key><string>{escape(str(values[key]))}</string>" for key in keys
        )
        data = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
                "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                "<plist version=\"1.0\"><dict>\n" + items + "\n</dict></plist>").encode()
        # The Go caller has already signed with the setup/certificate tuple
        # from this bag. Preserve that bag's authenticateAccount endpoint too;
        # mixing the legacy tuple with forced native/fast is rejected at the
        # edge before Apple can evaluate the account.
        bag_session = requests.Session()
        configure_transport(bag_session)
        with bag_session.get(
            "https://init.itunes.apple.com/bag.xml",
            params={"ix": "6", "guid": str(values["guid"])},
            headers={"User-Agent": headers.get("User-Agent", ""), "Accept": "application/xml, text/xml, */*"},
            timeout=20,
        ) as bag_response:
            if bag_response.status_code != 200:
                raise ValueError("Store bag unavailable")
            raw_auth = plistlib.loads(bag_response.content).get("authenticateAccount", "")
        bag_session.close()
        matched = urlsplit(raw_auth)
        matched_allowed = matched.hostname in {"auth.itunes.apple.com", "buy.itunes.apple.com"} or re.fullmatch(
            r"p[0-9]+-buy\.itunes\.apple\.com", matched.hostname or ""
        )
        if matched.scheme != "https" or not matched_allowed or matched.username or matched.fragment:
            raise ValueError("unsupported matched Store endpoint")
        request_url = raw_auth
    session = requests.Session()
    configure_transport(session)
    with session.request(
        message["method"], request_url, headers=headers,
        data=data, allow_redirects=False,
        timeout=20, stream=True,
    ) as response:
        parts = []
        length = 0
        for part in response.iter_content(16384):
            length += len(part)
            if length > 2 * 1024 * 1024:
                raise ValueError("response too large")
            parts.append(part)
        result_headers = {
            name: response.raw.headers.getlist(name) for name in response.raw.headers
            if name.lower() not in {"content-length", "content-encoding", "transfer-encoding"}
        }
        json.dump({
            "status": response.status_code, "headers": result_headers,
            "body": base64.b64encode(b"".join(parts)).decode("ascii"),
        }, sys.stdout)
    session.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print('{"error":"direct-https-transport-failed"}')
        sys.exit(1)
