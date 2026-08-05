#!/usr/bin/env python3
"""A *strictly* conforming reference CI — the suite's own proof that it can be satisfied.

`hull/scripts/fake-ci.py` is the spec's minimal illustration and it fails some of this suite's checks
(see README.md, "Baseline"). That leaves a question a conformance suite must answer about itself:
are those failures the subject's, or the harness's? This stand-in exists to settle it. It implements
the same contract as `fake-ci.py` plus exactly the clauses `fake-ci.py` omits — `errored` on a fetch
or extract failure (§7), refusing an unknown contract major (§13), re-hashing the archive to `tree_id`
before running it (§6, design D§4.2), and sanitising `summary` (§14.5) — and the suite goes green
against it end to end.

It is a test fixture, not a runner:

    !!  IT EXECUTES THE FETCHED TREE'S TEST SCRIPT AS A PLAIN SUBPROCESS ON THIS HOST.  !!

That is a direct violation of spec §14.1 ("a plain host subprocess is NOT sufficient") and is
acceptable here only because the sole thing that ever reaches it is a tree this very repository's
harness generated. Never point it at a real Hull. Set `STRICT_CI_RUN=0` to disable execution entirely
(the §14.5 summary check then passes vacuously, which the suite says so in a comment).

Usage:
    python3 tests/reference/strict-ci.py <port> [shared-secret]
"""
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9098
SECRET = sys.argv[2] if len(sys.argv) > 2 else ""
CONTRACT_VERSION = "1"
SUMMARY_MAX_CHARS = 200
RUN_CHECKS = os.environ.get("STRICT_CI_RUN", "1") != "0"

# §14.4: cap captured output so a job cannot OOM the runner by flooding logs.
MAX_CAPTURED_BYTES = 256 * 1024
JOB_TIMEOUT_SECS = 60

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[@-Z\\-_]")
BIDI = re.compile("[‎‏‪-‮⁦-⁩]")


def sanitize_summary(raw, max_chars=SUMMARY_MAX_CHARS):
    """§14.5: job output is untrusted data. Strip escapes and control characters, collapse to one
    line, and cap the length. Mirrors hull_ci_proto::sanitize_summary."""
    text = ANSI.sub("", raw)
    text = BIDI.sub("", text)
    text = "".join(" " if ord(c) < 0x20 or ord(c) == 0x7F else c for c in text)
    text = " ".join(text.split())
    return text[:max_chars]


def tree_id_of(members):
    """The harness's OPAQUE canonical tree hash (see tests/src/tree.rs). Re-hashing the *extracted*
    tree and comparing to the dispatch's tree_id is what §6 permits and design D§4.2 makes mandatory.

    This implements `HULL_CI_TREE_ID=opaque` only — the suite's default, and the mode a CI that
    cannot compute a keel address should be judged in. In `HULL_CI_TREE_ID=keel` the suite advertises
    a genuine keel tree id (BLAKE3 over keel's canonical object encoding), which this stand-in has no
    way to reproduce from the standard library; it would then report `errored` for every job, and
    correctly so. Run this reference in the default mode.

    `members` are (path, kind, mode, payload) tuples, where `payload` is a file's bytes or a
    symlink's target path — which is exactly what keel addresses a link by, so the two modes agree
    about *what* is hashed even though they disagree about how."""
    h = hashlib.sha256()
    h.update(b"hull-ci-conformance/tree/v1\n")
    for path, kind, mode, payload in sorted(members, key=lambda m: m[0]):
        if kind == "link":
            h.update(f"link 120000 {len(payload)} {path}\n".encode())
        else:
            h.update(f"file {mode:06o} {len(payload)} {path}\n".encode())
        h.update(payload)
    return h.hexdigest()


class Errored(Exception):
    """Our failure, not the code's — §7 says this is `errored`, never `red`."""

    def __init__(self, reason, summary):
        super().__init__(summary)
        self.reason = reason
        self.summary = summary


def fetch_and_verify(job):
    """§6: GET source_url (content-addressed, never git), verify, extract. Returns a work directory."""
    try:
        with urllib.request.urlopen(job["source_url"], timeout=30) as r:
            data = r.read()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        raise Errored("infra", f"could not fetch source_url: {e}") from e

    try:
        tf = tarfile.open(fileobj=io.BytesIO(data))
        # Directory entries carry no content and are implied by the paths under them, so they are not
        # part of the address in either mode — but they ARE part of the archive Hull serves, which is
        # why they are skipped explicitly here rather than assumed absent.
        members = [
            (m.name, "link", m.mode, m.linkname.encode())
            if m.issym()
            else (m.name, "file", m.mode, tf.extractfile(m).read())
            for m in tf.getmembers()
            if m.isfile() or m.issym()
        ]
    except (tarfile.TarError, OSError) as e:
        raise Errored("infra", f"source archive is not a readable tar: {e}") from e

    actual = tree_id_of(members)
    if actual != job["tree_id"]:
        raise Errored(
            "infra",
            f"tree_id mismatch: dispatch named {job['tree_id'][:12]}, archive hashes to {actual[:12]}",
        )

    workdir = tempfile.mkdtemp(prefix="strict-ci-")
    tf2 = tarfile.open(fileobj=io.BytesIO(data))
    try:
        tf2.extractall(workdir, filter="data")  # rejects ../ escapes, links, setuid (§14 / D§4.2)
    except (tarfile.TarError, OSError) as e:
        raise Errored("infra", f"extraction refused: {e}") from e
    return workdir


def run_checks(workdir):
    """Autodetect and run. Returns (status, summary). NOT a sandbox — see the module docstring."""
    if not RUN_CHECKS:
        return "green", "checks skipped (STRICT_CI_RUN=0)"

    if os.path.exists(os.path.join(workdir, "run-tests.sh")):
        argv = ["sh", "run-tests.sh"]
    elif os.path.exists(os.path.join(workdir, "Makefile")):
        argv = ["make", "test"]
    else:
        # §9.1 leans on this case: nothing to run is `errored`, not green.
        raise Errored("no_tests", "no test entry point detected in the tree")

    try:
        proc = subprocess.run(
            argv,
            cwd=workdir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=JOB_TIMEOUT_SECS,
            env={"PATH": "/usr/bin:/bin", "HOME": workdir},  # §14.2: scrubbed environment
        )
    except subprocess.TimeoutExpired as e:
        raise Errored("timeout", f"job exceeded {JOB_TIMEOUT_SECS}s") from e
    except OSError as e:
        raise Errored("infra", f"could not start the job: {e}") from e

    output = proc.stdout[:MAX_CAPTURED_BYTES].decode("utf-8", "replace")
    status = "green" if proc.returncode == 0 else "red"
    tail = output.strip().splitlines()[-1] if output.strip() else ""
    return status, sanitize_summary(f"{argv[0]} exited {proc.returncode}: {tail}")


def do_job(job):
    try:
        workdir = fetch_and_verify(job)
        status, summary = run_checks(workdir)
        body = {"status": status, "summary": summary}
    except Errored as e:
        # §7: infrastructure problems are `errored` so Hull never memoises our outage.
        body = {"status": "errored", "summary": sanitize_summary(e.summary), "reason": e.reason}

    headers = {"Content-Type": "application/json"}
    if SECRET:
        headers["X-Hull-CI-Secret"] = SECRET  # §8
    req = urllib.request.Request(
        job["callback_url"],  # §5: opaque, used verbatim
        data=json.dumps(body).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            print(f"[strict-ci] {body['status']} → callback [{resp.status}]", flush=True)
    except Exception as e:  # noqa: BLE001 — §10: a lost callback is reported, never fatal
        print(f"[strict-ci] callback failed: {e}", flush=True)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _refuse(self, code, why):
        payload = json.dumps({"error": why}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        print(f"[strict-ci] refused {code}: {why}", flush=True)

    def do_POST(self):
        # §8 — the secret is checked before anything else, and a *missing* header fails too.
        if SECRET and self.headers.get("X-Hull-CI-Secret") != SECRET:
            return self._refuse(401, "bad or missing X-Hull-CI-Secret")

        # §13 — an unknown major renames or re-means fields; refuse rather than guess.
        version = self.headers.get("X-Hull-CI-Version")
        if version is not None and version != CONTRACT_VERSION:
            return self._refuse(400, f"unsupported contract version {version}")

        try:
            job = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        except (ValueError, TypeError, KeyError) as e:
            return self._refuse(400, f"unreadable dispatch body: {e}")
        for field in ("repo", "change", "tree_id", "source_url", "callback_url"):
            if not str(job.get(field, "")).strip():
                return self._refuse(400, f"dispatch is missing {field}")
        # §5 — everything else in the body is ignored, including fields we have never heard of.

        payload = b'{"accepted":true}'
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

        print(
            f"[strict-ci] dispatch v{version}: {job['repo']} change={job['change'][:12]} "
            f"tree={job['tree_id'][:12]}",
            flush=True,
        )
        # §5 — acknowledge now, verdict later. A duplicate dispatch simply runs again and, because
        # the tree is content-addressed and the checks are deterministic, re-affirms the same verdict.
        threading.Thread(target=do_job, args=(job,), daemon=True).start()


if __name__ == "__main__":
    print(
        f"[strict-ci] listening on :{PORT}{' (secret set)' if SECRET else ''}"
        f"{'' if RUN_CHECKS else ' — check execution disabled'}",
        flush=True,
    )
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
