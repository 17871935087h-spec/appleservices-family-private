import sys
sys.dont_write_bytecode = True

import importlib.util
import copy
import hashlib
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


LEGACY_TARGET = "m123456789abcde@icloud.com"


def legacy_empty_snapshot(**overrides):
    value = {
        "http_status": 200,
        "response_bytes": 420,
        "parsed": True,
        "account_info_present": True,
        "primary_field_present": True,
        "primary_field_empty": True,
        "primary_state": "empty",
        "primary_address": None,
        "response_identity": "matched",
        "apple_mail_aliases": [],
        "mail_flags": {},
        "account_info_path": "appleAccountInfo",
        "schema_top": ["appleAccountInfo"],
        "schema_account_info": ["dsPrsID", "iCloudAppleIdAlias", "locked", "statusCode"],
        "business_error": False,
        "account_locked": False,
        "account_status_code": 2,
    }
    value.update(overrides)
    return value


def legacy_rejected_response(**overrides):
    value = {
        "http_status": 200,
        "response_bytes": 48,
        "success_field": False,
        "updatePersonErrorCode": -20103,
    }
    value.update(overrides)
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

    def legacy_fingerprint(self):
        material = "\x00".join((
            "acct-1", self.apple_id.strip().casefold(), "dsid-1", "adsid-1",
        )).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def legacy_record(self):
        return {
            "version": 1,
            "fingerprint": self.legacy_fingerprint(),
            "account_id": "acct-1",
            "utc": "2026-11-05T00:00:00+00:00",
            "activation_attempts": 2,
            "settings_before": legacy_empty_snapshot(),
            "status": "outcome_unknown",
            "target": LEGACY_TARGET,
            "activation_response": legacy_rejected_response(),
            "settings_after": legacy_empty_snapshot(),
            "updated_utc": "2026-11-05T00:00:03+00:00",
            "header_correction": {
                "profile": "xkji-header-correction-v1",
                "attempt": 2,
                "status": "response_observed",
                "utc": "2026-11-05T00:00:02+00:00",
                "reason": (
                    "static_sample_proves_legacy_User_Agent_and_setup_update_account_ui_Referer"
                ),
                "settings_before": legacy_empty_snapshot(),
                "activation_response": legacy_rejected_response(),
            },
        }

    def write_legacy(self, record=None):
        directory = self.account / "primary-mail-once"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "operation.json"
        path.write_text(json.dumps(record or self.legacy_record()), encoding="utf-8")
        return path

    def assert_legacy_unknown(self, record, native=None):
        path = self.write_legacy(record)
        before = path.read_bytes()
        services = FakeServices([native or native_empty()])
        result = primary_mail.run_request(self.request(), services)
        self.assertEqual(result["stage"], "outcome_unknown")
        self.assertFalse(result["can_create"])
        self.assertEqual(path.read_bytes(), before)
        return result, services

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

    def test_status_recovers_exact_legacy_rejection_read_only(self):
        path = self.write_legacy()
        before = path.read_bytes()
        services = FakeServices([native_empty()])

        result = primary_mail.run_request(self.request(), services)

        self.assertEqual(result["stage"], "not_open")
        self.assertTrue(result["can_create"])
        self.assertEqual(result["target"], LEGACY_TARGET)
        self.assertEqual(services.reads, 1)
        self.assertEqual(services.session_calls, 0)
        self.assertFalse((self.account / "primary-mail").exists())
        self.assertEqual(path.read_bytes(), before)

    def test_create_reuses_only_the_recorded_target_and_saves_source_digest(self):
        path = self.write_legacy()
        original = path.read_bytes()
        validations = [
            {"mail_service_present": False, "mail_flag": False,
             "primary_email_matches_target": False},
            {"mail_service_present": True, "mail_flag": True,
             "primary_email_matches_target": False},
        ]
        web = FakeWebClient({}, validations)
        services = FakeServices([native_empty(), native_present(LEGACY_TARGET)], web)

        result = primary_mail.run_request(
            self.request("create", confirm_permanent=True, prefix=""), services,
        )

        self.assertEqual(result["stage"], "verified")
        self.assertEqual(result["target"], LEGACY_TARGET)
        self.assertEqual(web.activation_seen, 1)
        operation = json.loads((self.account / "primary-mail" / "operation.json").read_text())
        self.assertEqual(operation["target"], LEGACY_TARGET)
        self.assertEqual(operation["legacy_source_sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(operation["activation_attempts"], 1)
        self.assertEqual(path.read_bytes(), original)

    def test_create_rejects_nonmatching_or_invalid_legacy_prefix_before_session(self):
        for prefix in ("different", None, 0, False):
            with self.subTest(prefix=prefix):
                self.write_legacy()
                services = FakeServices([native_empty()])

                result = primary_mail.run_request(
                    self.request("create", confirm_permanent=True, prefix=prefix), services,
                )

                self.assertEqual(result["stage"], "invalid_request")
                self.assertEqual(result["target"], LEGACY_TARGET)
                self.assertEqual(services.session_calls, 0)

    def test_legacy_unknown_fields_binding_status_and_attempt_counts_stay_blocked(self):
        changes = [
            {"version": True}, {"version": 2}, {"account_id": "other"},
            {"fingerprint": "0" * 64}, {"fingerprint": "not-a-hash"},
            {"activation_attempts": 1}, {"activation_attempts": 3},
            {"activation_attempts": True}, {"status": "verified"},
            {"utc": "not-a-time"}, {"updated_utc": "not-a-time"},
            {"extra": "unknown"}, {"settings_before": None},
        ]
        for change in changes:
            with self.subTest(change=change):
                record = dict(self.legacy_record(), **change)
                self.assert_legacy_unknown(record)

        correction_changes = [
            {"profile": "other"}, {"attempt": 1}, {"attempt": 3},
            {"attempt": True}, {"status": "intent"}, {"utc": "bad"},
            {"reason": "other"}, {"extra": "unknown"},
            {"settings_before": None}, {"activation_response": None},
        ]
        for change in correction_changes:
            with self.subTest(correction_change=change):
                record = self.legacy_record()
                record["header_correction"].update(change)
                self.assert_legacy_unknown(record)

    def test_corrupt_or_duplicate_key_legacy_json_stays_blocked(self):
        path = self.write_legacy()
        for raw in (b'{"version":', b'{"version":1,"version":1}'):
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                before = path.read_bytes()
                services = FakeServices([native_empty()])
                result = primary_mail.run_request(self.request(), services)
                self.assertEqual(result["stage"], "outcome_unknown")
                self.assertFalse(result["can_create"])
                self.assertEqual(path.read_bytes(), before)

    def test_each_legacy_response_must_be_the_exact_complete_rejection(self):
        anomalies = [
            {"http_status": 201}, {"http_status": True},
            {"response_bytes": 47}, {"response_bytes": None},
            {"success_field": True}, {"success_field": 0},
            {"updatePersonErrorCode": -1}, {"updatePersonErrorCode": "-20103"},
            {"updatePersonErrorCode": True}, {"extra": "unknown"},
        ]
        for location in ("activation_response", "header_correction"):
            for anomaly in anomalies:
                with self.subTest(location=location, anomaly=anomaly):
                    record = self.legacy_record()
                    if location == "activation_response":
                        record[location].update(anomaly)
                    else:
                        record[location]["activation_response"].update(anomaly)
                    self.assert_legacy_unknown(record)

        for location in ("activation_response", "header_correction"):
            with self.subTest(location=location, missing_field=True):
                record = self.legacy_record()
                response = (record[location] if location == "activation_response"
                            else record[location]["activation_response"])
                del response["updatePersonErrorCode"]
                self.assert_legacy_unknown(record)

    def test_each_legacy_empty_snapshot_must_be_complete_and_identity_matched(self):
        mutations = [
            {"response_identity": "mismatch"}, {"primary_field_empty": False},
            {"primary_state": "existing_aliases"},
            {"apple_mail_aliases": ["alias@icloud.com"]},
            {"account_locked": True}, {"business_error": True},
            {"account_status_code": 1}, {"extra": "unknown"},
        ]
        locations = (
            ("settings_before",), ("settings_after",),
            ("header_correction", "settings_before"),
        )
        for location in locations:
            for mutation in mutations:
                with self.subTest(location=location, mutation=mutation):
                    record = self.legacy_record()
                    target = record
                    for part in location:
                        target = target[part]
                    target.update(mutation)
                    self.assert_legacy_unknown(record)

        native_mutations = [
            {"response_identity": "mismatch"}, {"primary_field_empty": False},
            {"primary_state": "existing_aliases"},
            {"apple_mail_aliases": ["alias@icloud.com"]},
            {"account_locked": True}, {"business_error": True},
        ]
        for mutation in native_mutations:
            with self.subTest(current_native=mutation):
                native = native_empty()
                native.update(mutation)
                self.assert_legacy_unknown(self.legacy_record(), native)

    def test_legacy_target_must_be_supported_canonical_icloud_address(self):
        for target in (
            "name@me.com", "name@gmail.com", "Abc@icloud.com",
            "a@icloud.com", "ab@icloud.com", "a..b@icloud.com",
            "sample@icloud.com", "m123456789abcdeg@icloud.com",
        ):
            with self.subTest(target=target):
                record = self.legacy_record()
                record["target"] = target
                self.assert_legacy_unknown(record)

    def test_legacy_symlink_and_second_legacy_block_recovery(self):
        path = self.write_legacy()
        original_is_symlink = Path.is_symlink

        def journal_is_symlink(candidate):
            if candidate == path:
                return True
            return original_is_symlink(candidate)

        with mock.patch.object(Path, "is_symlink", journal_is_symlink):
            services = FakeServices([native_empty()])
            result = primary_mail.run_request(self.request(), services)
        self.assertEqual(result["stage"], "outcome_unknown")
        self.assertEqual(services.session_calls, 0)

        other = self.account / "mail-mccgateway-once"
        other.mkdir()
        services = FakeServices([native_empty()])
        result = primary_mail.run_request(self.request(), services)
        self.assertEqual(result["stage"], "outcome_unknown")
        self.assertEqual(services.session_calls, 0)

    def test_existing_new_operation_blocks_recovered_legacy(self):
        self.write_legacy()
        mail_dir = self.account / "primary-mail"
        mail_dir.mkdir()
        (mail_dir / "operation.json").write_text(
            json.dumps({"stage": "intent", "target": LEGACY_TARGET}), encoding="utf-8",
        )
        services = FakeServices([native_empty()])

        result = primary_mail.run_request(
            self.request("create", confirm_permanent=True), services,
        )

        self.assertEqual(result["stage"], "outcome_unknown")
        self.assertEqual(result["target"], LEGACY_TARGET)
        self.assertEqual(services.session_calls, 0)

    def test_legacy_digest_is_rechecked_after_web_preflight_before_intent(self):
        path = self.write_legacy()
        record = self.legacy_record()

        class MutatingWebClient(FakeWebClient):
            def availability(inner_self, target):
                super(MutatingWebClient, inner_self).availability(target)
                changed = copy.deepcopy(record)
                changed["updated_utc"] = "2026-11-05T00:00:04+00:00"
                path.write_text(json.dumps(changed), encoding="utf-8")

        web = MutatingWebClient({}, [
            {"mail_service_present": False, "mail_flag": False,
             "primary_email_matches_target": False},
        ])
        services = FakeServices([native_empty()], web)
        result = primary_mail.run_request(
            self.request("create", confirm_permanent=True), services,
        )

        self.assertEqual(result["stage"], "outcome_unknown")
        self.assertEqual(web.activation_seen, 0)
        self.assertFalse((self.account / "primary-mail" / "operation.json").exists())

    def test_unknown_legacy_operation_is_never_replayed(self):
        path = self.write_legacy()
        original = path.read_bytes()
        web = FakeWebClient({}, [
            {"mail_service_present": False, "mail_flag": False,
             "primary_email_matches_target": False},
        ])
        services = FakeServices([native_empty()], web)
        request = self.request("create", confirm_permanent=True)

        first = primary_mail.run_request(request, services)
        second = primary_mail.run_request(request, services)

        self.assertEqual(first["stage"], "outcome_unknown")
        self.assertEqual(second["stage"], "outcome_unknown")
        self.assertEqual(web.activation_seen, 1)
        self.assertEqual(path.read_bytes(), original)

    def test_no_saved_session_and_no_web_login_authorization_does_not_login(self):
        self.write_legacy()

        class NoLoginServices(FakeServices):
            def web_session(inner_self, context, request):
                inner_self.session_calls += 1
                return primary_mail.load_or_login_web_session(context, request)

        services = NoLoginServices([native_empty()])
        result = primary_mail.run_request(
            self.request("create", confirm_permanent=True, allow_web_login=False), services,
        )

        self.assertEqual(result["stage"], "web_login_required")
        self.assertEqual(result["target"], LEGACY_TARGET)
        self.assertEqual(services.session_calls, 1)
        self.assertFalse((self.account / "primary-mail" / "login-intent.json").exists())
        self.assertFalse((self.account / "primary-mail" / "operation.json").exists())

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

    def test_legacy_recovery_does_not_hide_a_later_login_hard_stop(self):
        self.write_legacy()
        mail_dir = self.account / "primary-mail"
        mail_dir.mkdir()
        (mail_dir / "login-intent.json").write_text("{}", encoding="utf-8")
        (mail_dir / "login-state.json").write_text(
            json.dumps({"stage": "risk_blocked"}), encoding="utf-8",
        )
        services = FakeServices([native_empty()])
        result = primary_mail.run_request(self.request(), services)
        self.assertEqual(result["stage"], "risk_blocked")
        self.assertEqual(result["target"], LEGACY_TARGET)
        self.assertFalse(result["can_create"])
        self.assertEqual(services.session_calls, 0)

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
