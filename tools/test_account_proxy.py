import base64
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True

TOOLS = Path(__file__).parent
ACCOUNT_PROXY_ENV = "APPLESERVICES_ACCOUNT_PROXY"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


primary_mail = load_module("primary_mail_proxy_test", TOOLS / "primary_mail.py")
skill_store = load_module("skill_store_transport_proxy_test", TOOLS / "skill-store-transport.py")


class FakeSession:
    def __init__(self):
        self.trust_env = True
        self.verify = False
        self.proxies = {}


class FakeMarker:
    def is_file(self):
        return True


class AccountProxyTests(unittest.TestCase):
    def native_transport(self):
        context = SimpleNamespace(dsid="synthetic-dsid", token="synthetic-token")
        return primary_mail.NativeTransport(context, {})

    def test_supported_proxy_schemes_and_auth_are_sent_to_helper(self):
        reply = {
            "status": 200,
            "body": base64.b64encode(b"{\"ok\":true}").decode("ascii"),
            "set_cookies": ["fixture=session; Path=/; Secure"],
        }
        for scheme in ("http", "https", "socks5", "socks5h"):
            with self.subTest(scheme=scheme):
                proxy = f"{scheme}://fixture-user:fixture-pass@proxy.invalid:8443"
                completed = SimpleNamespace(returncode=0, stdout=json.dumps(reply).encode("utf-8"))
                with mock.patch.dict(os.environ, {ACCOUNT_PROXY_ENV: proxy}, clear=False):
                    with mock.patch.object(primary_mail.subprocess, "run", return_value=completed) as run:
                        result = primary_mail._account_proxy_response(
                            "POST", "https://setup.icloud.com/setup/get_account_settings",
                            b"fixture-body", {"X-Fixture": "fixture-header"}, 1024, 15,
                        )
                self.assertEqual(result, (200, b"{\"ok\":true}", ["fixture=session; Path=/; Secure"]))
                args, kwargs = run.call_args
                self.assertEqual(Path(args[0][0]).name, "account-http.exe")
                self.assertEqual(kwargs["env"][ACCOUNT_PROXY_ENV], proxy)
                self.assertNotIn("APPLESERVICES_PASSWORD", kwargs["env"])
                self.assertNotIn("HTTP_PROXY", kwargs["env"])
                payload = json.loads(kwargs["input"])
                self.assertEqual(payload, {
                    "method": "POST",
                    "url": "https://setup.icloud.com/setup/get_account_settings",
                    "body": base64.b64encode(b"fixture-body").decode("ascii"),
                    "headers": {"X-Fixture": "fixture-header"},
                    "byte_limit": 1024,
                    "timeout_seconds": 15,
                })
                self.assertLessEqual(kwargs["timeout"], 30)

    def test_webclient_external_http_client_path_uses_pipe_helper(self):
        reply = {
            "status": 200,
            "body": base64.b64encode(b"{\"success\":true}").decode("ascii"),
            "set_cookies": [],
        }
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(reply).encode("utf-8"))
        client = primary_mail.WebClient.__new__(primary_mail.WebClient)
        client.session = {}
        client.record = {}
        client.calls = set()
        client.gateway = ""
        client.cookies = [{
            "name": "fixture", "value": "cookie", "domain": "icloud.com",
            "path": "/", "host_only": False, "secure": True,
        }]
        client.agent = "fixture-agent"
        client.host = "www.icloud.com"
        client.setup_host = "setup.icloud.com"
        proxy = "http://fixture-user:fixture-pass@proxy.invalid:8080"
        with mock.patch.dict(os.environ, {ACCOUNT_PROXY_ENV: proxy}, clear=False):
            with mock.patch.object(primary_mail.subprocess, "run", return_value=completed) as run:
                result = client.request("POST", "https://setup.icloud.com/setup/ws/1/validate", {})
        self.assertEqual(result, {"success": True})
        self.assertEqual(json.loads(run.call_args.kwargs["input"])["method"], "POST")

    def test_loopback_is_direct_and_does_not_start_proxy_helper(self):
        proxy = "http://fixture-user:fixture-pass@proxy.invalid:8080"
        with mock.patch.dict(os.environ, {ACCOUNT_PROXY_ENV: proxy}, clear=False):
            with mock.patch.object(primary_mail.subprocess, "run") as run:
                self.assertIsNone(primary_mail._account_proxy_response(
                    "GET", "http://127.0.0.1:18741/api/status", None, {}, 1024, 5,
                ))
                self.assertIsNone(primary_mail._account_proxy_response(
                    "GET", "http://localhost:18741/api/status", None, {}, 1024, 5,
                ))
        run.assert_not_called()

    def test_no_proxy_keeps_existing_direct_http_client_path(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ACCOUNT_PROXY_ENV, None)
            os.environ.pop("APPLESERVICES_PROXY_POOL", None)
            self.assertIsNone(primary_mail._account_proxy_response(
                "GET", "https://setup.icloud.com/setup/get_account_settings", None, {}, 1024, 5,
            ))

    def test_login_helper_receives_only_explicit_account_proxy(self):
        proxy = "socks5h://fixture-user:fixture-pass@proxy.invalid:1080"
        with mock.patch.dict(os.environ, {
            ACCOUNT_PROXY_ENV: proxy,
            "APPLESERVICES_PROXY_POOL": r"D:\DevData\proxy-pool\pool.json",
            "APPLESERVICES_PASSWORD": "must-not-propagate",
            "HTTP_PROXY": "http://ambient.invalid:8080",
        }, clear=False):
            env = primary_mail.helper_environment(Path(r"D:\DevData\proxy-tests\tmp"))
        self.assertEqual(env[ACCOUNT_PROXY_ENV], proxy)
        self.assertNotIn("APPLESERVICES_PASSWORD", env)
        self.assertNotIn("APPLESERVICES_PROXY_POOL", env)
        self.assertNotIn("HTTP_PROXY", env)
        self.assertEqual(env["NO_PROXY"], "127.0.0.1,localhost,::1")
        self.assertEqual(env["no_proxy"], "127.0.0.1,localhost,::1")

    def test_malformed_proxy_fails_closed_without_direct_fallback(self):
        direct = mock.Mock()
        with mock.patch.dict(os.environ, {
            ACCOUNT_PROXY_ENV: "https://fixture-user:private@proxy.invalid/path",
        }, clear=False):
            with mock.patch.object(primary_mail.subprocess, "run") as run:
                with mock.patch.object(primary_mail.http.client, "HTTPSConnection", direct):
                    with self.assertRaises(primary_mail.Stop) as raised:
                        self.native_transport().request("GET", primary_mail.SETTINGS_PATH, None, {})
        run.assert_not_called()
        direct.assert_not_called()
        self.assertNotIn("private", str(raised.exception))

    def test_configured_pool_without_account_proxy_fails_closed(self):
        direct = mock.Mock()
        with mock.patch.dict(os.environ, {
            "APPLESERVICES_PROXY_POOL": r"D:\DevData\proxy-pool\pool.json",
        }, clear=False):
            os.environ.pop(ACCOUNT_PROXY_ENV, None)
            with mock.patch.object(primary_mail.subprocess, "run") as run:
                with mock.patch.object(primary_mail.http.client, "HTTPSConnection", direct):
                    with self.assertRaises(primary_mail.Stop):
                        self.native_transport().request("GET", primary_mail.SETTINGS_PATH, None, {})
        run.assert_not_called()
        direct.assert_not_called()

    def test_proxy_helper_failure_never_falls_back_or_leaks_proxy_url(self):
        proxy = "http://fixture-user:private@proxy.invalid:8080"
        direct = mock.Mock()
        completed = SimpleNamespace(returncode=1, stdout=b"private proxy URL must not leak")
        with mock.patch.dict(os.environ, {ACCOUNT_PROXY_ENV: proxy}, clear=False):
            with mock.patch.object(primary_mail.subprocess, "run", return_value=completed):
                with mock.patch.object(primary_mail.http.client, "HTTPSConnection", direct):
                    with self.assertRaises(primary_mail.Stop) as raised:
                        self.native_transport().request("GET", primary_mail.SETTINGS_PATH, None, {})
        direct.assert_not_called()
        self.assertNotIn("private", str(raised.exception))
        self.assertNotIn("must not leak", str(raised.exception))

    def test_proxy_helper_rejects_bad_output_and_oversized_body(self):
        proxy = "http://fixture-user:fixture-pass@proxy.invalid:8080"
        bad_replies = [
            {"status": 200, "body": "not-base64", "set_cookies": []},
            {"status": True, "body": "", "set_cookies": []},
            {"status": 200, "body": base64.b64encode(b"too large").decode("ascii"), "set_cookies": []},
        ]
        for reply in bad_replies:
            with self.subTest(reply=reply.get("status")):
                completed = SimpleNamespace(returncode=0, stdout=json.dumps(reply).encode("utf-8"))
                with mock.patch.dict(os.environ, {ACCOUNT_PROXY_ENV: proxy}, clear=False):
                    with mock.patch.object(primary_mail.subprocess, "run", return_value=completed):
                        with self.assertRaises(primary_mail.Stop):
                            primary_mail._account_proxy_response(
                                "GET", "https://setup.icloud.com/path", None, {}, 4, 5,
                            )

    def test_store_transport_proxy_overrides_marker_and_fails_closed(self):
        proxy = "https://fixture-user:fixture-pass@proxy.invalid:8443"
        session = FakeSession()
        with mock.patch.dict(os.environ, {ACCOUNT_PROXY_ENV: proxy}, clear=False):
            with mock.patch.object(skill_store, "PROXY_MARKER", FakeMarker()):
                skill_store.configure_transport(session)
        self.assertEqual(session.proxies, {"http": proxy, "https": proxy})
        self.assertFalse(session.trust_env)
        self.assertTrue(session.verify)

        bad_session = FakeSession()
        with mock.patch.dict(os.environ, {
            ACCOUNT_PROXY_ENV: "https://fixture-user:private@proxy.invalid/path",
        }, clear=False):
            with mock.patch.object(skill_store, "PROXY_MARKER", FakeMarker()):
                with self.assertRaises(ValueError) as raised:
                    skill_store.configure_transport(bad_session)
        self.assertEqual(bad_session.proxies, {})
        self.assertNotIn("private", str(raised.exception))

    def test_store_transport_preserves_legacy_marker_when_pool_is_unset(self):
        session = FakeSession()
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ACCOUNT_PROXY_ENV, None)
            os.environ.pop("APPLESERVICES_PROXY_POOL", None)
            with mock.patch.object(skill_store, "PROXY_MARKER", FakeMarker()):
                skill_store.configure_transport(session)
        self.assertEqual(session.proxies, {
            "http": "http://127.0.0.1:10808",
            "https": "http://127.0.0.1:10808",
        })
        self.assertFalse(session.trust_env)
        self.assertTrue(session.verify)

    def test_store_pool_without_account_proxy_does_not_fall_back_to_marker(self):
        session = FakeSession()
        with mock.patch.dict(os.environ, {
            "APPLESERVICES_PROXY_POOL": r"D:\DevData\proxy-pool\pool.json",
        }, clear=False):
            os.environ.pop(ACCOUNT_PROXY_ENV, None)
            with mock.patch.object(skill_store, "PROXY_MARKER", FakeMarker()):
                with self.assertRaises(ValueError):
                    skill_store.configure_transport(session)
        self.assertEqual(session.proxies, {})


if __name__ == "__main__":
    unittest.main()
