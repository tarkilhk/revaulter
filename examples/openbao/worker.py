#!/usr/bin/env python3
"""One-shot trusted worker for a fixed OpenBao Shamir 2-of-3 target.

Only an encrypted Revaulter envelope is stored. Plaintext stays in this process
and its CLI child and is never included in status output or error details.
"""

import base64
import binascii
import fcntl
import json
import os
import tempfile
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


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise WorkerError("Enrollment contains duplicate fields")
        result[key] = value
    return result


def read_enrollment(config):
    # Read one inode once so atomic enrollment replacement cannot mix generations
    with open(config["enrollment_file"], "rb") as source:
        data = source.read(65537)
    if len(data) > 65536:
        raise WorkerError("Enrollment is too large")
    enrollment = json.loads(data, object_pairs_hook=unique_object)
    if (not isinstance(enrollment, dict)
            or set(enrollment) != {"version", "userId", "target", "envelope", "requestKey", "trust", "updatedAt"}
            or type(enrollment["version"]) is not int or enrollment["version"] != 1
            or not isinstance(enrollment["userId"], str) or not enrollment["userId"]
            or enrollment["target"] != https_origin(config["openbao_url"])
            or not isinstance(enrollment["requestKey"], str)
            or not enrollment["requestKey"].startswith("rvk_")):
        raise WorkerError("Enrollment does not match this worker")
    envelope = enrollment["envelope"]
    if (not isinstance(envelope, dict)
            or set(envelope) != {"kind", "algorithm", "keyLabel", "value", "nonce", "tag"}
            or envelope["kind"] != "revaulter/1"
            or envelope["algorithm"] != "A256GCM"
            or envelope["keyLabel"] != "openbao-unseal"):
        raise WorkerError("Encrypted envelope is invalid")
    for field, minimum, maximum in (("value", 1, 4096), ("nonce", 12, 12), ("tag", 16, 16)):
        value = envelope[field]
        if not isinstance(value, str):
            raise WorkerError("Encrypted envelope is invalid")
        try:
            decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        except (ValueError, binascii.Error):
            raise WorkerError("Encrypted envelope is invalid") from None
        if (not minimum <= len(decoded) <= maximum
                or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value):
            raise WorkerError("Encrypted envelope is invalid")
    trust = enrollment["trust"]
    expected_key = https_origin(config["revaulter_url"]) + "|" + enrollment["userId"]
    if (not isinstance(trust, dict) or set(trust) != {"entries"}
            or not isinstance(trust["entries"], dict)
            or set(trust["entries"]) != {expected_key}):
        raise WorkerError("Enrollment trust does not match this worker")
    entry = trust["entries"][expected_key]
    if (not isinstance(entry, dict)
            or set(entry) != {"anchorEs384PublicKey", "anchorMldsa87PublicKey", "fingerprint", "firstSeen"}
            or any(not isinstance(value, str) or not value for value in entry.values())):
        raise WorkerError("Enrollment trust is invalid")
    return enrollment


def decrypt_bundle(config):
    enrollment = read_enrollment(config)
    # Only the request credential and public trust pins reach these private files
    # The CLI receives ciphertext on stdin and returns plaintext through a pipe
    with tempfile.TemporaryDirectory(prefix="openbao-approval-") as directory:
        request_key = Path(directory) / "request-key"
        trust_store = Path(directory) / "trust.json"
        for path, content in ((request_key, enrollment["requestKey"]),
                              (trust_store, json.dumps(enrollment["trust"]))):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="ascii") as output:
                output.write(content)
        command = [
            config["cli"], "decrypt", "--server", https_origin(config["revaulter_url"]),
            "--request-key-file", str(request_key),
            "--trust-store", str(trust_store),
            "--json", "-", "--format", "raw", "--timeout", "5m",
            "--note", "OpenBao unseal 2 of 3",
        ]
        try:
            result = subprocess.run(
                command, input=json.dumps(enrollment["envelope"]).encode("ascii"),
                capture_output=True, timeout=330, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise WorkerError("Approval failed or timed out") from None
    if result.returncode != 0:
        raise WorkerError("Approval denied, failed, or expired")
    try:
        return json.loads(result.stdout, object_pairs_hook=unique_object)
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
