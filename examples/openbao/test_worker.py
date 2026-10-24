"""Dummy-material tests; these never contact an OpenBao or Revaulter server."""
import base64
import json
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import worker


class FakeBao:
    def __init__(self, succeed=True):
        self.sealed = True
        self.shares = []
        self.succeed = succeed

    def status(self):
        return {"initialized": True, "type": "shamir", "t": 2, "n": 3, "sealed": self.sealed}

    def submit(self, share):
        self.shares.append(share)
        self.sealed = not (self.succeed and len(self.shares) == 2)
        return self.status()


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.config = {"openbao_url": "https://bao.example"}
        self.bundle = {
            "version": 1, "target": "https://bao.example",
            "shares": [base64.b64encode(bytes([n]) * 33).decode() for n in (1, 2)],
        }

    def test_two_approved_shares_are_consumed_and_cleared(self):
        bao = FakeBao()
        expected = self.bundle["shares"][:]
        status = worker.unseal(self.config, bao, lambda _: self.bundle)
        self.assertEqual(status, "unsealed")
        self.assertEqual(bao.shares, expected)
        self.assertEqual(self.bundle, {})

    def test_already_unsealed_never_requests_material(self):
        bao = FakeBao()
        bao.sealed = False
        with patch.object(worker, "decrypt_bundle") as decrypt:
            status = worker.unseal(self.config, bao, decrypt)
        self.assertEqual(status, "already-unsealed")
        decrypt.assert_not_called()

    def test_denial_submits_nothing(self):
        bao = FakeBao()
        with self.assertRaises(worker.WorkerError):
            worker.unseal(self.config, bao, lambda _: (_ for _ in ()).throw(worker.WorkerError("denied")))
        self.assertEqual(bao.shares, [])

    def test_wrong_target_or_duplicate_shares_submits_nothing(self):
        for change in ({"target": "https://wrong.example"}, {"shares": ["same", "same"]}):
            with self.subTest(change=change):
                bao = FakeBao()
                bundle = {**self.bundle, **change}
                with self.assertRaises(worker.WorkerError):
                    worker.unseal(self.config, bao, lambda _: bundle)
                self.assertEqual(bao.shares, [])

    def test_wrong_threshold_submits_nothing(self):
        bao = FakeBao()
        bao.status = lambda: {"initialized": True, "type": "shamir", "t": 1, "n": 3, "sealed": True}
        with self.assertRaises(worker.WorkerError):
            worker.unseal(self.config, bao, lambda _: self.bundle)
        self.assertEqual(bao.shares, [])

    def test_failure_after_shares_does_not_return_success(self):
        with self.assertRaises(worker.WorkerError):
            worker.unseal(self.config, FakeBao(succeed=False), lambda _: self.bundle)

    def enrollment(self, directory):
        encode = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
        record = {
            "version": 1, "userId": "owner", "target": "https://bao.example",
            "updatedAt": "2026-10-24T00:00:00Z", "requestKey": "rvk_dummy",
            "envelope": {"kind": "revaulter/1", "algorithm": "A256GCM", "keyLabel": "openbao-unseal",
                         "value": encode(b"ciphertext"), "nonce": encode(bytes(12)), "tag": encode(bytes(16))},
            "trust": {"entries": {"https://approve.example|owner": {
                "anchorEs384PublicKey": "synthetic", "anchorMldsa87PublicKey": "synthetic",
                "fingerprint": "synthetic", "firstSeen": "2026-10-24T00:00:00Z"}}},
        }
        path = Path(directory) / "enrollment.json"
        path.write_text(json.dumps(record))
        config = {**self.config, "revaulter_url": "https://approve.example", "enrollment_file": str(path),
                  "cli": "/opt/revaulter-cli"}
        return config, record, path

    def test_cli_uses_private_ephemeral_credentials_and_only_ciphertext(self):
        with tempfile.TemporaryDirectory() as directory:
            config, record, _ = self.enrollment(directory)
            paths = []
            def invoke(command, **kwargs):
                for flag in ("--request-key-file", "--trust-store"):
                    path = Path(command[command.index(flag) + 1])
                    paths.append(path)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
                    self.assertNotIn(self.bundle["shares"][0], path.read_text())
                self.assertEqual(json.loads(kwargs["input"]), record["envelope"])
                self.assertNotIn("--no-trust-store", command)
                self.assertNotIn("--insecure", command)
                return subprocess.CompletedProcess([], 0, json.dumps(self.bundle).encode(), b"")
            with patch.object(worker.subprocess, "run", side_effect=invoke):
                bundle = worker.decrypt_bundle(config)
            self.assertEqual(bundle, self.bundle)
            self.assertTrue(all(not path.exists() for path in paths))

    def test_cli_failure_cleans_credentials_and_hides_output(self):
        with tempfile.TemporaryDirectory() as directory:
            config, _, _ = self.enrollment(directory)
            result = subprocess.CompletedProcess([], 1, b"sensitive-dummy-output", b"sensitive-dummy-error")
            with patch.object(worker.subprocess, "run", return_value=result) as run:
                with self.assertRaises(worker.WorkerError) as error:
                    worker.decrypt_bundle(config)
            self.assertNotIn("sensitive-dummy", str(error.exception))
            command = run.call_args.args[0]
            self.assertFalse(Path(command[command.index("--request-key-file") + 1]).exists())

    def test_replacement_routes_to_the_saving_account(self):
        with tempfile.TemporaryDirectory() as directory:
            config, record, path = self.enrollment(directory)
            for user_id in ("first-user", "second-user"):
                replacement = {**record, "userId": user_id, "requestKey": "rvk_" + user_id,
                               "trust": {"entries": {"https://approve.example|" + user_id:
                                         record["trust"]["entries"]["https://approve.example|owner"]}}}
                path.write_text(json.dumps(replacement))
                def invoke(command, **kwargs):
                    key_path = Path(command[command.index("--request-key-file") + 1])
                    trust_path = Path(command[command.index("--trust-store") + 1])
                    self.assertEqual(key_path.read_text(), replacement["requestKey"])
                    self.assertEqual(json.loads(trust_path.read_text()), replacement["trust"])
                    return subprocess.CompletedProcess([], 0, json.dumps(self.bundle).encode(), b"")
                with patch.object(worker.subprocess, "run", side_effect=invoke):
                    self.assertEqual(worker.decrypt_bundle(config), self.bundle)

    def test_mismatched_enrollment_is_rejected_before_cli(self):
        changes = ({"userId": "other"}, {"target": "https://other.example"},
                   {"trust": {"entries": {}}}, {"shares": ["plaintext"]},
                   {"version": True})
        with tempfile.TemporaryDirectory() as directory:
            config, record, path = self.enrollment(directory)
            for change in changes:
                path.write_text(json.dumps({**record, **change}))
                with patch.object(worker.subprocess, "run") as run:
                    with self.assertRaises(worker.WorkerError):
                        worker.decrypt_bundle(config)
                    run.assert_not_called()
            path.write_text(json.dumps(record).replace('"version": 1', '"version": 1, "version": 1'))
            with self.assertRaises(worker.WorkerError):
                worker.read_enrollment(config)
            path.write_text(" " * 65537)
            with self.assertRaises(worker.WorkerError):
                worker.read_enrollment(config)

    def test_https_and_no_redirects(self):
        for origin in ("http://bao.example", "https://u:p@bao.example", "https://bao.example/path"):
            with self.assertRaises(worker.WorkerError):
                worker.https_origin(origin)
        with self.assertRaises(worker.WorkerError):
            worker.NoRedirect().redirect_request(None, None, 302, "", {}, "https://wrong.example")


if __name__ == "__main__":
    unittest.main()
