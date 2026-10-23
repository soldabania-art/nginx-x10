#!/usr/bin/env bash
# Run an immutable selection of the official nginx-tests without patching it.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
exec python3 - "$script_dir/../.." "$@" <<'PY'
import argparse
import datetime
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import subprocess
import sys
import tempfile
import time

root = Path(sys.argv[1]).resolve()
parser = argparse.ArgumentParser(description="Pinned official nginx-tests compatibility sample")
parser.add_argument("--binary", default=str(root / "x10/.build/objs/nginx"))
parser.add_argument("--tests-dir", default=str(root / "x10/.build/nginx-tests"))
parser.add_argument("--output", help="Also write the JSON report to this path")
parser.add_argument("--process-mode", choices=["master"], default="master")
parser.add_argument("--timeout", type=int, help="Per-file timeout in seconds, 5..180")
args = parser.parse_args(sys.argv[2:])
metadata = json.loads((root / "x10/test/official-tests.json").read_text())
timeout = metadata["defaultTimeoutSeconds"] if args.timeout is None else args.timeout
if not 5 <= timeout <= 180:
    parser.error("--timeout must be an integer from 5 to 180")

binary = Path(args.binary).resolve()
checkout = Path(args.tests_dir).resolve()
report = {
    "schemaVersion": 1,
    "suite": "official-nginx-tests-curated",
    "startedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "source": {"repository": metadata["repository"], "revision": metadata["revision"],
               "license": metadata["license"]},
    "processMode": args.process_mode,
    "timeoutSecondsPerFile": timeout,
    "timeoutOverridesSeconds": {} if args.timeout else metadata.get("timeoutOverridesSeconds", {}),
    "unsafeTestsEnabled": False,
    "tests": [],
    "cleanupErrors": [],
    "limitations": [
        "Curated sample, not the complete official suite or all module/platform combinations.",
        "Optional dependencies may produce explicit upstream skips; skipped assertions are not passes.",
        "One native worker is used unless an upstream fixture specifies otherwise; not all multiworker behavior is covered.",
        "No HTTP/3/QUIC interoperability, network-loss testing or performance claim follows from this run.",
    ],
}
active_process = None

def interrupted(number, _frame):
    report["interruptedBySignal"] = signal.Signals(number).name
    raise RuntimeError("Interrupted by " + signal.Signals(number).name)

for number in [signal.SIGINT, signal.SIGTERM]:
    signal.signal(number, interrupted)

def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def command(argv, cwd=None, limit=120):
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=limit)
    if result.returncode:
        raise RuntimeError(f"{argv[0]} exited {result.returncode}: {result.stderr[-4000:].strip()}")
    return result.stdout.strip()

def terminate_group(process):
    # Every test starts in its own session; never signal a caller's process group.
    previous = {number: signal.signal(number, signal.SIG_IGN)
                for number in [signal.SIGINT, signal.SIGTERM]}
    try:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)
        # Reaping the Perl leader does not mean its forked native children have
        # already exited. SIGKILL delivery is asynchronous; wait for the owned
        # session group to disappear before deleting the fixture directory.
        deadline = time.monotonic() + 2
        while True:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Test process group remained after SIGKILL")
            time.sleep(0.02)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report["cleanupErrors"].append(str(error))
        raise RuntimeError("Could not clean up the test process group: " + str(error))
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)

tap_parser = r'''
use strict;
use warnings;
use JSON::PP;
use TAP::Parser;
local $/;
open(my $f, '<', $ARGV[0]) or die $!;
my $tap = <$f>;
my $p = TAP::Parser->new({tap => $tap});
my %counts = (run => 0, passed => 0, failed => 0, skipped => 0,
              todoFailed => 0, todoPassed => 0);
my @skips;
my @failures;
my @bailouts;
while (my $r = $p->next) {
    if ($r->is_bailout) { push @bailouts, $r->explanation; }
    next unless $r->is_test;
    $counts{run}++;
    if ($r->has_skip) {
        $counts{skipped}++;
        push @skips, $r->explanation;
    } elsif ($r->has_todo) {
        $counts{$r->is_actual_ok ? 'todoPassed' : 'todoFailed'}++;
    } elsif ($r->is_actual_ok) {
        $counts{passed}++;
    } else {
        $counts{failed}++;
        push @failures, $r->as_string;
    }
}
my @errors = $p->parse_errors;
print JSON::PP->new->canonical->encode({assertions => \%counts,
    skipAll => $p->skip_all, skipReasons => \@skips, failures => \@failures,
    parseErrors => \@errors, bailouts => \@bailouts,
    hasProblems => $p->has_problems ? JSON::PP::true : JSON::PP::false});
'''

try:
    if os.name != "posix":
        raise RuntimeError("This runner currently requires a POSIX host")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError("--binary must name an executable regular file")
    if not re.fullmatch(r"[A-Za-z0-9_./+-]+", str(binary)):
        raise RuntimeError("Use a binary path without spaces or shell metacharacters; upstream invokes it through a shell")
    command(["perl", "-MTest::More", "-MTAP::Parser", "-MJSON::PP", "-e", "1"])
    if not re.fullmatch(r"[0-9a-f]{40}", metadata["revision"]):
        raise RuntimeError("The official test revision must be a full pinned commit")
    if not checkout.exists():
        checkout.parent.mkdir(parents=True, exist_ok=True)
        command(["git", "clone", "--no-checkout", "--depth", "1", metadata["repository"], str(checkout)])
        command(["git", "fetch", "--depth", "1", "origin", metadata["revision"]], cwd=checkout)
        command(["git", "checkout", "--detach", metadata["revision"]], cwd=checkout)
    if command(["git", "rev-parse", "HEAD"], cwd=checkout) != metadata["revision"]:
        raise RuntimeError("The test checkout does not match the pinned revision; use a separate clean checkout")
    if command(["git", "status", "--porcelain", "--untracked-files=all"], cwd=checkout):
        raise RuntimeError("The official test checkout is not clean; tests must remain unmodified")
    if digest(checkout / metadata["license"]["file"]) != metadata["license"]["sha256"]:
        raise RuntimeError("The pinned upstream license hash differs")
    identity = binary.stat()
    version = subprocess.run([str(binary), "-V"], text=True, capture_output=True, timeout=10)
    if version.returncode:
        raise RuntimeError("nginx -V failed")
    report["binary"] = {"sha256": digest(binary), "bytes": identity.st_size,
                        "versionOutput": version.stderr.strip()}
    dependencies = command(["perl", "-MJSON::PP", "-e",
        'my %r; for my $m (qw(IO::Socket::SSL Net::SSLeay FCGI SCGI Compress::Zlib)) '
        '{ eval "require $m"; $r{$m} = $@ ? JSON::PP::false : JSON::PP::true; } '
        'print JSON::PP->new->canonical->encode(\\%r);'])
    report["optionalPerlModules"] = json.loads(dependencies)
    # h2.t deliberately tests reload/GOAWAY; replacing master semantics makes
    # that test invalid. Keep the official native master/worker default.
    globals = ""
    if os.geteuid() == 0:
        user, group = pwd.getpwuid(os.geteuid()).pw_name, grp.getgrgid(os.getegid()).gr_name
        if not all(re.fullmatch(r"[A-Za-z0-9_.-]+", value) for value in [user, group]):
            raise RuntimeError("Cannot safely represent the current uid/gid names as native directives")
        globals = f"user {user} {group}; " + globals
    report["testGlobals"] = globals
    state = root / "x10/.build"
    state.mkdir(parents=True, exist_ok=True)
    # Serialize this suite to prevent two local invocations contending for fixtures.
    import fcntl
    lock = (state / "official-tests.lock").open("a")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError("Another official-tests run holds the fixture lock")
    with tempfile.TemporaryDirectory(prefix="official-tests-", dir=state) as temporary:
        temporary = Path(temporary)
        for family, tests in metadata["families"].items():
            for name in tests:
                if not re.fullmatch(r"[a-z0-9_]+\.t", name) or not (checkout / name).is_file():
                    raise RuntimeError("Invalid or missing curated test file: " + name)
                print("official-tests: " + name, file=sys.stderr, flush=True)
                env = {k: v for k, v in os.environ.items()
                       if not k.startswith(("TEST_NGINX_", "HARNESS_")) and k not in ("PERL5OPT", "PERL5LIB")}
                case_dir = temporary / name
                case_dir.mkdir()
                env.update(TEST_NGINX_BINARY=str(binary), TEST_NGINX_GLOBALS=globals,
                           TMPDIR=str(case_dir))
                output, errors = case_dir / "stdout.tap", case_dir / "stderr.log"
                started = time.monotonic()
                timed_out = False
                case_timeout = args.timeout or metadata.get("timeoutOverridesSeconds", {}).get(name, timeout)
                with output.open("wb") as stdout, errors.open("wb") as stderr:
                    try:
                        active_process = subprocess.Popen(["perl", str(checkout / name)], cwd=checkout,
                            env=env, stdout=stdout, stderr=stderr, start_new_session=True)
                        code = active_process.wait(timeout=case_timeout)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        terminate_group(active_process)
                        code = active_process.returncode
                    finally:
                        if active_process is not None:
                            terminate_group(active_process)
                            active_process = None
                parsed = json.loads(command(["perl", "-e", tap_parser, str(output)], limit=10))
                skipped = bool(parsed["skipAll"]) and parsed["assertions"]["run"] == 0
                passed = code == 0 and not timed_out and not parsed["hasProblems"]
                item = {"file": name, "family": family, "sourceSha256": digest(checkout / name),
                        "status": "skipped" if passed and skipped else "passed" if passed else "failed",
                        "exitCode": code, "timedOut": timed_out, "timeoutSeconds": case_timeout,
                        "durationMs": round((time.monotonic() - started) * 1000), **parsed}
                if not passed:
                    item["stderrTail"] = errors.read_text(errors="replace")[-6000:]
                    item["tapTail"] = output.read_text(errors="replace")[-6000:]
                report["tests"].append(item)
    if command(["git", "rev-parse", "HEAD"], cwd=checkout) != metadata["revision"] or command(
            ["git", "status", "--porcelain", "--untracked-files=all"], cwd=checkout):
        raise RuntimeError("The official source checkout changed during the run")
    if digest(binary) != report["binary"]["sha256"]:
        raise RuntimeError("The native binary changed during the run")
    report["sourceUnchangedDuringTest"] = True
    totals = {key: 0 for key in ["run", "passed", "failed", "skipped", "todoFailed", "todoPassed"]}
    for item in report["tests"]:
        for key, count in item["assertions"].items():
            totals[key] += count
    report["summary"] = {"files": len(report["tests"]),
        "filesPassed": sum(t["status"] == "passed" for t in report["tests"]),
        "filesSkipped": sum(t["status"] == "skipped" for t in report["tests"]),
        "filesFailed": sum(t["status"] == "failed" for t in report["tests"]),
        "assertions": totals}
    report["success"] = report["summary"]["filesFailed"] == 0 and not report["cleanupErrors"]
except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
    report["success"] = False
    report["error"] = str(error)
finally:
    if active_process is not None:
        try:
            terminate_group(active_process)
        except RuntimeError:
            report["success"] = False
    report["finishedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        destination = Path(args.output).resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(encoded)
    print(encoded, end="")
sys.exit(0 if report.get("success") else 1)
PY
