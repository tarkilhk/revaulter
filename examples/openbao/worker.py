#!/usr/bin/env python3
"""One-shot trusted worker for a fixed OpenBao Shamir 2-of-3 target.

Only an encrypted Revaulter envelope is stored. Plaintext stays in this process
and its CLI child and is never included in status output or error details.
"""

import base64
import binascii
import fcntl
import json
import resource
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class WorkerError(Exception):
    """An error safe to return to the triggering CI job."""


def https_origin(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        raise WorkerError("A fixed HTTPS origin is required")
    return value.rstrip("/")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise WorkerError("HTTP redirects are refused")


class BaoClient:
    def __init__(self, origin, ca_file=None):
        self.origin = https_origin(origin)
        context = ssl.create_default_context(cafile=ca_file)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=context))

    def request(self, path, body=None):
        data = None if body is None else json.dumps(body).encode("ascii")
        request = urllib.request.Request(
            self.origin + "/v1/sys/" + path, data=data,
            headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=15) as response:
                return json.loads(response.read(65536))
        except (OSError, ValueError, urllib.error.URLError):
            # OpenBao errors can reflect submitted input, so never emit bodies
            raise WorkerError("OpenBao request failed") from None

    def status(self):
        return self.request("seal-status")

    def submit(self, share):
        return self.request("unseal", {"key": share})


def require_target(status):
    if (not isinstance(status, dict) or status.get("initialized") is not True
            or status.get("type") != "shamir" or status.get("t") != 2
            or status.get("n") != 3 or type(status.get("sealed")) is not bool):
        raise WorkerError("Target must be an initialized OpenBao Shamir 2-of-3 node")


def decrypt_bundle(config):
    https_origin(config["revaulter_url"])
    envelope_path = Path(config["envelope"])
    envelope = json.loads(envelope_path.read_text())
    if envelope.get("keyLabel") != config["key_label"] or envelope.get("algorithm") != "A256GCM":
        raise WorkerError("Encrypted envelope does not match the configured key label and algorithm")
    command = [
        config["cli"], "decrypt", "--server", config["revaulter_url"],
        "--request-key-file", config["request_key_file"],
        "--trust-store", config["trust_store"],
        "--json", "-", "--format", "raw", "--timeout", "5m",
        "--note", "OpenBao unseal 2 of 3",
    ]
    try:
        result = subprocess.run(
            command, input=json.dumps(envelope).encode("ascii"),
            capture_output=True, timeout=330, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise WorkerError("Approval failed or timed out") from None
    if result.returncode != 0:
        raise WorkerError("Approval denied, failed, or expired")
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise WorkerError("Approved bundle is invalid") from None


def validate_bundle(bundle, origin):
    if (not isinstance(bundle, dict) or set(bundle) != {"version", "target", "shares"}
            or bundle["version"] != 1 or bundle["target"] != origin):
        raise WorkerError("Approved bundle does not match this target")
    shares = bundle["shares"]
    if (not isinstance(shares, list) or len(shares) != 2
            or any(not isinstance(share, str) for share in shares)
            or shares[0] == shares[1]):
        raise WorkerError("Bundle must contain exactly two distinct base64 shares")
    for share in shares:
        try:
            raw = base64.b64decode(share, validate=True)
        except (ValueError, binascii.Error):
            raise WorkerError("Bundle contains an invalid base64 share") from None
        if len(raw) != 33:
            raise WorkerError("Bundle contains an invalid Shamir share length")
    return shares


def unseal(config, bao=None, decrypt=decrypt_bundle):
    origin = https_origin(config["openbao_url"])
    bao = bao or BaoClient(origin, config.get("ca_file"))
    status = bao.status()
    require_target(status)
    if not status["sealed"]:
        return "already-unsealed"
    bundle = decrypt(config)
    try:
        shares = validate_bundle(bundle, origin)
        # Check again after phone approval in case another operator unsealed it
        status = bao.status()
        require_target(status)
        if not status["sealed"]:
            return "already-unsealed"
        for share in shares:
            result = bao.submit(share)
            require_target(result)
            if not result["sealed"]:
                final = bao.status()
                require_target(final)
                if not final["sealed"]:
                    return "unsealed"
                break
        raise WorkerError("OpenBao remained sealed after the approved shares")
    finally:
        # Python cannot guarantee erasure of immutable strings; the process exits
        if isinstance(bundle, dict):
            bundle.clear()


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if len(sys.argv) != 2:
        raise WorkerError("Usage: worker.py /absolute/path/to/worker.json")
    config = json.loads(Path(sys.argv[1]).read_text())
    # A local lock coalesces callers and prevents duplicate approval requests
    with open(config["lock_file"], "a", encoding="ascii") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise WorkerError("An unseal request is already pending") from None
        print(json.dumps({"status": unseal(config)}))


if __name__ == "__main__":
    try:
        main()
    except WorkerError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        sys.exit(1)
    except Exception:
        # Do not leak plaintext-bearing exception messages or traceback frames
        print('{"error":"Worker failed; check its local configuration"}', file=sys.stderr)
        sys.exit(1)
