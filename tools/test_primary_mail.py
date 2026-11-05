import sys
sys.dont_write_bytecode = True

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).with_name("primary_mail.py")
SPEC = importlib.util.spec_from_file_location("primary_mail", MODULE_PATH)
primary_mail = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = primary_mail
SPEC.loader.exec_module(primary_mail)

TEST_ROOT = Path(r"D:\ClawBox\test-runs")


def native_empty():
    return {
        "http_status": 200,
        "parsed": True,
        "account_info_present": True,
        "primary_field_present": True,
        "primary_field_empty": True,
        "primary_state": "empty",
        "primary_address": None,
        "response_identity": "matched",
        "apple_mail_aliases": [],
        "business_error": False,
        "account_locked": False,
    }


def native_present(address):
    value = native_empty()
    value.update(
        primary_field_empty=False,
        primary_state="present",
        primary_address=address,
    )
    return value


def native_unknown():
    value = native_empty()
    value.update(
        http_status=0,
        account_info_present=False,
        primary_field_present=False,
        primary_field_empty=False,
        primary_state="unknown",
        response_identity="absent",
        business_error=None,
        account_locked=None,
    )
    return value


class FakeWebClient:
    def __init__(self, record, validations=None):
        self.record = record
        self.validations = list(validations or [])
        self.validations_seen = 0
        self.availability_seen = 0
        self.activation_seen = 0

    def validate(self, expected_apple_id, expected_dsid, target):
        self.validations_seen += 1
        if self.validations:
            return self.validations.pop(0)
        return {
            "mail_service_present": True,
            "mail_flag": True,
            # Apple dsInfo.primaryEmail remains the Apple ID after Mail2 creation.
            "primary_email_matches_target": False,
        }

    def availability(self, target):
        self.availability_seen += 1

    def activate(self, target):
        self.activation_seen += 1
        return {"email": target}


class FakeServices:
    def __init__(self, native_values=None, web_client=None):
        self.native_values = list(native_values or [native_empty()])
        self.reads = 0
        self.session_calls = 0
        self.client = web_client

    def native_read(self, context, request):
        self.reads += 1
        if len(self.native_values) > 1:
            return self.native_values.pop(0)
        return self.native_values[0]

    def web_session(self, context, request):
        self.session_calls += 1
        return {"fixture": True}

    def web_client(self, session, record):
        if self.client is None:
            self.client = FakeWebClient(record)
        self.client.record = record
        return self.client

    def now(self):
        return "2026-11-05T00:00:00Z"


class PrimaryMailTests(unittest.TestCase):
    def setUp(self):
        TEST_ROOT.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="primary-mail-", dir=str(TEST_ROOT))
        self.base = Path(self.temp.name)
        self.root = self.base / "state"
        self.account = self.root / "accounts" / "acct-1"
        self.account.mkdir(parents=True)
        self.apple_id = "owner@icloud.com"
        (self.root / "accounts.json").write_text(
            json.dumps({
                "accounts": [{
                    "id": "acct-1",
                    "apple_id": self.apple_id,
                    "dir": str(self.account),
                }]
            }),
            encoding="utf-8",
        )
        (self.account / "session.json").write_text(
            json.dumps({"AppleID": self.apple_id, "DSID": "adsid-1"}),
            encoding="utf-8",
        )
        (self.account / "icloud-accepted.json").write_text(
            json.dumps({
                "adsid": "adsid-1",
                "session": {
                    "AppleID": self.apple_id,
                    "DSID": "dsid-1",
                    "Tokens": {"mmeAuthToken": "synthetic-token"},
                },
                "service-data": {},
            }),
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp.cleanup()

    def request(self, action="status", **overrides):
        value = {
            "action": action,
            "root": str(self.root),
            "account_id": "acct-1",
            "apple_id": self.apple_id,
            "prefix": "",
            "allow_web_login": False,
            "confirm_permanent": False,
            "library": r"D:\synthetic\library.dll",
            "python": r"D:\synthetic\python.exe",
            "login_helper": r"D:\synthetic\login.exe",
            "native_helper": r"D:\synthetic\native.exe",
            "dashboard_url": "http://127.0.0.1:18741",
        }
        value.update(overrides)
        return value

    def test_status_not_open_is_read_only_and_can_create(self):
        services = FakeServices([native_empty()])
        result = primary_mail.run_request(self.request(), services)

        self.assertEqual(result["stage"], "not_open")
        self.assertTrue(result["can_create"])
        self.assertFalse((self.account / "primary-mail").exists())
        self.assertEqual(services.reads, 1)

    def test_status_existing_operation_blocks_create(self):
        mail_dir = self.account / "primary-mail"
        mail_dir.mkdir()
        (mail_dir / "operation.json").write_text(
            json.dumps({"stage": "intent", "target": "abc123@icloud.com"}),
            encoding="utf-8",
        )
        result = primary_mail.run_request(self.request(), FakeServices([native_unknown()]))

        self.assertEqual(result["stage"], "outcome_unknown")
        self.assertEqual(result["target"], "abc123@icloud.com")
        self.assertFalse(result["can_create"])

    def test_status_legacy_intent_blocks_create_without_mutating_history(self):
        legacy = self.account / "mail-mccgateway-once"
        legacy.mkdir()
        record = legacy / "operation.json"
        record.write_text("fixture history", encoding="utf-8")

        result = primary_mail.run_request(self.request(), FakeServices([native_empty()]))

        self.assertEqual(result["stage"], "outcome_unknown")
        self.assertFalse(result["can_create"])
        self.assertEqual(record.read_text(encoding="utf-8"), "fixture history")

    def test_status_preserves_failed_login_hard_stop(self):
        mail_dir = self.account / "primary-mail"
        mail_dir.mkdir()
        (mail_dir / "login-intent.json").write_text("{}", encoding="utf-8")
        (mail_dir / "login-state.json").write_text(
            json.dumps({"stage": "verification_required"}),
            encoding="utf-8",
        )

        result = primary_mail.run_request(self.request(), FakeServices([native_empty()]))

        self.assertEqual(result["stage"], "verification_required")
        self.assertFalse(result["can_create"])

    def test_status_verified_uses_native_exact_address(self):
        address = "abc123@icloud.com"
        result = primary_mail.run_request(
            self.request(),
            FakeServices([native_present(address)]),
        )

        self.assertEqual(result["stage"], "verified")
        self.assertEqual(result["email"], address)
        self.assertFalse(result["can_create"])

    def test_create_requires_permanent_confirmation(self):
        services = FakeServices([native_empty()])
        result = primary_mail.run_request(
            self.request("create", prefix="sample"),
            services,
        )

        self.assertEqual(result["stage"], "invalid_request")
        self.assertEqual(services.reads, 0)
        self.assertFalse((self.account / "primary-mail").exists())

    def test_create_existing_primary_never_calls_web_or_replaces_address(self):
        address = "existing@icloud.com"
        services = FakeServices([native_present(address)])
        result = primary_mail.run_request(
            self.request("create", prefix="requested", confirm_permanent=True),
            services,
        )

        self.assertEqual(result["stage"], "verified")
        self.assertEqual(result["email"], address)
        self.assertEqual(services.session_calls, 0)

    def test_create_reconciles_existing_intent_without_replay(self):
        mail_dir = self.account / "primary-mail"
        mail_dir.mkdir()
        (mail_dir / "operation.json").write_text(
            json.dumps({"stage": "intent", "target": "sample@icloud.com"}),
            encoding="utf-8",
        )
        services = FakeServices([native_unknown(), native_unknown()])
        result = primary_mail.run_request(
            self.request("create", prefix="sample", confirm_permanent=True),
            services,
        )

        self.assertEqual(result["stage"], "outcome_unknown")
        self.assertEqual(result["target"], "sample@icloud.com")
        self.assertEqual(services.session_calls, 0)
        self.assertEqual(services.reads, 1)

    def test_create_uses_native_exact_match_not_web_dsinfo_primary_email(self):
        target = "sample@icloud.com"
        validations = [
            {
                "mail_service_present": False,
                "mail_flag": False,
                "primary_email_matches_target": False,
            },
            {
                "mail_service_present": True,
                "mail_flag": True,
                "primary_email_matches_target": False,
            },
        ]
        web = FakeWebClient({}, validations)
        services = FakeServices([native_empty(), native_present(target)], web)

        result = primary_mail.run_request(
            self.request(
                "create",
                prefix="sample",
                confirm_permanent=True,
                allow_web_login=False,
            ),
            services,
        )

        self.assertEqual(result["stage"], "verified")
        self.assertEqual(result["email"], target)
        self.assertEqual(result["target"], target)
        self.assertEqual(web.activation_seen, 1)
        self.assertEqual(web.availability_seen, 1)
        self.assertEqual(web.validations_seen, 2)
        record = json.loads((self.account / "primary-mail" / "operation.json").read_text(encoding="utf-8"))
        self.assertEqual(record["stage"], "verified")
        self.assertTrue(record["native_readback_matches_target"])
        self.assertNotIn("primary_email_matches_target", record["web_after"])

    def test_legacy_me_and_mac_addresses_are_unavailable_not_open(self):
        for address in ("old@me.com", "old@mac.com"):
            reply = primary_mail.NativeReply(200, json.dumps({
                "appleAccountInfo": {
                    "dsPrsID": "dsid-1",
                    "locked": False,
                    "iCloudAppleIdAlias": address,
                }
            }).encode())
            safe = primary_mail.safe_settings(reply, "dsid-1")

            self.assertEqual(primary_mail.stage_from_native(safe), "unavailable")
            self.assertFalse(primary_mail.current_primary_reply("acct-1", safe, True)["can_create"])

    def test_prefix_matches_ui_and_gateway_contract(self):
        self.assertEqual(primary_mail.make_target("abc_1"), "abc_1@icloud.com")
        for value in ("ab", "1abc", "a-bc", "A_bc"):
            with self.subTest(value=value):
                with self.assertRaises(primary_mail.Stop):
                    primary_mail.make_target(value)

    def test_dpapi_is_mocked_for_synthetic_credential_fixture(self):
        context = primary_mail.resolve_context(self.request())
        ciphertext = b"synthetic-protected-data"
        framed = primary_mail.CREDENTIAL_HEADER + len(ciphertext).to_bytes(4, "big") + ciphertext
        (self.account / "credential.dpapi").write_bytes(framed)
        calls = []

        def fake_unprotect(data, protect, entropy):
            calls.append((bytes(data), protect, entropy))
            return b"synthetic-password"

        with mock.patch.object(primary_mail, "_crypt_data", side_effect=fake_unprotect):
            password, plaintext = primary_mail.load_password(context)

        self.assertEqual(password, "synthetic-password")
        self.assertEqual(calls[0][0], ciphertext)
        self.assertFalse(calls[0][1])
        self.assertEqual(calls[0][2], primary_mail.credential_entropy(self.apple_id))
        self.assertEqual(bytes(plaintext), b"synthetic-password")


if __name__ == "__main__":
    unittest.main()
