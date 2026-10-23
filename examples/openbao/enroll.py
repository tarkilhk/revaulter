#!/usr/bin/env python3
"""Interactively enroll two shares without plaintext files or command arguments.

Run only on an operator-controlled enrollment device, never on CI, HA or dev.
"""
import getpass
import json
import resource
import subprocess
import sys
from pathlib import Path

from worker import BaoClient, WorkerError, https_origin, require_target, validate_bundle


def enroll(config, prompt=getpass.getpass):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if prompt is getpass.getpass and not sys.stdin.isatty():
        raise WorkerError("Enrollment requires an interactive terminal")
    origin = https_origin(config["openbao_url"])
    https_origin(config["revaulter_url"])
    require_target(BaoClient(origin, config.get("ca_file")).status())
    output = Path(config["envelope"])
    if output.exists():
        raise WorkerError("Encrypted envelope already exists; choose a new enrollment destination")
    bundle = {"version": 1, "target": origin, "shares": [prompt("First base64 unseal share: "), prompt("Second base64 unseal share: ")]}
    try:
        validate_bundle(bundle, origin)
        command = [
            config["cli"], "encrypt", "--server", config["revaulter_url"],
            "--request-key-file", config["request_key_file"],
            "--trust-store", config["trust_store"],
            "--algorithm", "A256GCM", "--key-label", config["key_label"],
            "--input", "-", "--note", "Enroll OpenBao unseal", "--timeout", "5m",
        ]
        result = subprocess.run(command, input=json.dumps(bundle).encode("ascii"), capture_output=True, timeout=330, check=False)
        if result.returncode != 0:
            raise WorkerError("Enrollment approval failed")
        try:
            encrypted = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            raise WorkerError("Enrollment did not return a valid encrypted envelope") from None
        if (encrypted.get("kind") != "revaulter/1" or encrypted.get("algorithm") != "A256GCM"
                or encrypted.get("keyLabel") != config["key_label"]):
            raise WorkerError("Enrollment returned an unexpected envelope")
        with output.open("xb") as destination:
            destination.write(result.stdout)
        output.chmod(0o600)
    finally:
        bundle.clear()


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise WorkerError("Usage: enroll.py /absolute/path/to/enrollment.json")
        enroll(json.loads(Path(sys.argv[1]).read_text()))
        print('{"status":"encrypted-envelope-created"}')
    except WorkerError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('{"error":"Enrollment failed"}', file=sys.stderr)
        sys.exit(1)
