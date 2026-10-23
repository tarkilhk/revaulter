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

    def test_cli_receives_only_ciphertext_and_secret_output_is_not_returned_as_status(self):
        with tempfile.TemporaryDirectory() as directory:
            envelope = Path(directory) / "ciphertext.json"
            envelope.write_text(json.dumps({"kind": "revaulter/1", "algorithm": "A256GCM", "keyLabel": "openbao-unseal", "value": "dummy-ciphertext"}))
            config = {**self.config, "revaulter_url": "https://approve.example", "envelope": str(envelope), "key_label": "openbao-unseal", "cli": "/opt/revaulter-cli", "request_key_file": "/etc/request-key", "trust_store": "/etc/trust.json"}
            result = subprocess.CompletedProcess([], 0, json.dumps(self.bundle).encode(), b"dummy diagnostic")
            with patch.object(worker.subprocess, "run", return_value=result) as run:
                bundle = worker.decrypt_bundle(config)
            command = run.call_args.args[0]
            self.assertNotIn(self.bundle["shares"][0], str(command))
            self.assertIn("--request-key-file", command)
            self.assertIn("--trust-store", command)
            self.assertNotIn("--no-trust-store", command)
            self.assertNotIn("--insecure", command)
            self.assertEqual(bundle, self.bundle)

    def test_cli_failure_does_not_expose_either_output_stream(self):
        with tempfile.TemporaryDirectory() as directory:
            envelope = Path(directory) / "ciphertext.json"
            envelope.write_text(json.dumps({"algorithm": "A256GCM", "keyLabel": "openbao-unseal"}))
            config = {"revaulter_url": "https://approve.example", "envelope": str(envelope), "key_label": "openbao-unseal", "cli": "/opt/cli", "request_key_file": "/etc/request-key", "trust_store": "/etc/trust.json"}
            result = subprocess.CompletedProcess([], 1, b"sensitive-dummy-output", b"sensitive-dummy-error")
            with patch.object(worker.subprocess, "run", return_value=result):
                with self.assertRaises(worker.WorkerError) as error:
                    worker.decrypt_bundle(config)
            self.assertNotIn("sensitive-dummy", str(error.exception))

    def test_https_and_no_redirects(self):
        for origin in ("http://bao.example", "https://u:p@bao.example", "https://bao.example/path"):
            with self.assertRaises(worker.WorkerError):
                worker.https_origin(origin)
        with self.assertRaises(worker.WorkerError):
            worker.NoRedirect().redirect_request(None, None, 302, "", {}, "https://wrong.example")


if __name__ == "__main__":
    unittest.main()
