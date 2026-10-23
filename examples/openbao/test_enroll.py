"""Enrollment regression tests with dummy shares and no real endpoints."""
import base64
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import enroll
import worker


class EnrollmentTests(unittest.TestCase):
    def test_only_ciphertext_is_written_and_shares_stay_out_of_arguments(self):
        shares = [base64.b64encode(bytes([n]) * 33).decode() for n in (1, 2)]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "encrypted.json"
            config = {"openbao_url": "https://bao.example", "revaulter_url": "https://approve.example", "envelope": str(output), "key_label": "openbao-unseal", "cli": "/opt/cli", "request_key_file": "/etc/request-key", "trust_store": "/etc/trust.json"}
            ciphertext = json.dumps({"kind": "revaulter/1", "algorithm": "A256GCM", "keyLabel": "openbao-unseal", "value": "dummy-ciphertext"}).encode()
            with patch.object(enroll, "BaoClient") as bao, patch.object(enroll.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, ciphertext, b"")) as run:
                bao.return_value.status.return_value = {"initialized": True, "type": "shamir", "t": 2, "n": 3, "sealed": True}
                values = iter(shares)
                enroll.enroll(config, lambda _: next(values))
            self.assertEqual(output.read_bytes(), ciphertext)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            for share in shares:
                self.assertNotIn(share, str(run.call_args.args[0]))
                self.assertNotIn(share.encode(), output.read_bytes())
            self.assertEqual(json.loads(run.call_args.kwargs["input"])["shares"], shares)

    def test_refuses_unmasked_noninteractive_input(self):
        with patch.object(enroll.sys.stdin, "isatty", return_value=False):
            with self.assertRaises(worker.WorkerError) as error:
                enroll.enroll({})
        self.assertIn("interactive terminal", str(error.exception))


if __name__ == "__main__":
    unittest.main()
