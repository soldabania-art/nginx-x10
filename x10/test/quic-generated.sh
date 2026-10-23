#!/usr/bin/env bash
# Deterministic generated properties; production source, ASan + UBSan by default.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source_dir=$(cd -- "$script_dir/../.." && pwd -P)
objects_dir=
seed=9000
cases=256
sanitizers=address,undefined

usage() {
    printf '%s\n' \
      'Usage: x10/test/quic-generated.sh [--source DIR] [--objs DIR]' \
      '       [--seed N] [--cases N] [--no-sanitize]' \
      'Defaults: selected checkout, generated build headers, seed 9000,' \
      '256 seeded cases plus a fixed boundary matrix, ASan + UBSan.' \
      'LeakSanitizer is explicitly disabled; this fixture checks bounds/UB.' \
      '--seed: 0..4294967295; --cases: 0..10000 (fixed matrix always runs).' \
      'JSON to stdout; nonzero on property, build, sanitizer or identity failure.'
}

while (($#)); do
    case "$1" in
        --source|--objs|--seed|--cases)
            if (($# < 2)); then usage >&2; exit 2; fi
            case "$1" in
                --source) source_dir=$2 ;;
                --objs) objects_dir=$2 ;;
                --seed) seed=$2 ;;
                --cases) cases=$2 ;;
            esac
            shift 2 ;;
        --seed=*) seed=${1#*=}; shift ;;
        --cases=*) cases=${1#*=}; shift ;;
        --no-sanitize) sanitizers=none; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

source_dir=$(cd -- "$source_dir" && pwd -P)
if [[ -z $objects_dir ]]; then
    for candidate in "$source_dir/x10/.build/objs" "$source_dir/objs-x10" \
                     "$source_dir/objs"; do
        if [[ -f $candidate/ngx_auto_config.h ]]; then
            objects_dir=$candidate
            break
        fi
    done
fi
if [[ -z $objects_dir || ! -f $objects_dir/ngx_auto_config.h ]]; then
    printf '%s\n' 'Generated headers missing; provide --objs from a configured build.' >&2
    exit 2
fi
objects_dir=$(cd -- "$objects_dir" && pwd -P)

python3 - "$source_dir" "$objects_dir" "$script_dir" "$seed" "$cases" \
    "$sanitizers" "${CC:-cc}" <<'PY'
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

source, objects, harness = map(Path, sys.argv[1:4])
seed_text, cases_text, sanitizers, compiler = sys.argv[4:]
if (re.fullmatch(r"[0-9]{1,10}", seed_text) is None
        or int(seed_text) > 4294967295
        or re.fullmatch(r"[0-9]{1,5}", cases_text) is None
        or int(cases_text) > 10000):
    print("--seed must be 0..4294967295 and --cases 0..10000", file=sys.stderr)
    sys.exit(2)
transport = source / "src/event/quic/ngx_event_quic_transport.c"
test = harness / "quic-generated.c"
config = objects / "ngx_auto_config.h"
sha256 = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
before = sha256(transport)
flags = ["-std=c99", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
         "-Wno-unused-parameter", "-ffunction-sections", "-fdata-sections"]
if sanitizers != "none":
    flags += ["-fsanitize=" + sanitizers, "-fno-sanitize-recover=all",
              "-fno-omit-frame-pointer"]
includes = [source / name for name in (
    "src/core", "src/event", "src/event/modules", "src/event/quic", "src/os/unix")]
includes.append(objects)
result = {
    "schemaVersion": 1,
    "suite": "quic-generated-properties",
    "startedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "source": "src/event/quic/ngx_event_quic_transport.c",
    "sourceCheckout": source.name,
    "sourceSha256": before,
    "harnessSha256": sha256(test),
    "generatedConfigSha256": sha256(config),
    "seed": int(seed_text),
    "randomCasesRequested": int(cases_text),
    "networkUsed": False,
    "duplicatePolicy": "excluded_unchanged",
    "scope": "Production transport-parameter parser with only logging stubbed; no handshake or apply-time semantic checks",
    "limitations": [
        "Six properties generate related inputs; case count is not independent protocol coverage",
        "Numeric-value constraints enforced by ngx_quic_apply_transport_params are outside this parser fixture",
        "64-bit Linux generated headers; no 32-bit, TLS-library or full QUIC interoperability claim",
        "Fixed-seed bounded generation is not exhaustive fuzzing or a security proof",
        "LeakSanitizer is explicitly disabled; memory-leak behavior is unverified",
    ],
}
version = re.search(r'#define\s+NGINX_VERSION\s+"([^"]+)"',
                    (source / "src/core/nginx.h").read_text())
result["nginxVersion"] = version.group(1)
try:
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=source,
                              capture_output=True, text=True, timeout=5)
    result["checkoutRevision"] = revision.stdout.strip() if revision.returncode == 0 else None
    identity = subprocess.run([compiler, "--version"], capture_output=True,
                              text=True, timeout=5, check=True)
    result["compiler"] = identity.stdout.splitlines()[0]
    result["compilerExecutable"] = compiler
    result["compilerFlags"] = flags
    result["sanitizers"] = {"requested": sanitizers,
                            "enabled": sanitizers.split(",") if sanitizers != "none" else [],
                            "leakDetection": False}
    with tempfile.TemporaryDirectory(prefix="nginx-x10-quic-generated-") as temporary:
        binary = Path(temporary) / "quic-generated"
        argv = [compiler, *flags, '-DNGX_QUIC_TRANSPORT_SOURCE="' + str(transport) + '"']
        for include in includes:
            argv += ["-I", str(include)]
        argv += [str(test), "-Wl,--gc-sections", "-o", str(binary)]
        built = subprocess.run(argv, capture_output=True, text=True, timeout=90)
        result["compileExitCode"] = built.returncode
        result["compilerDiagnostics"] = built.stderr
        if built.returncode != 0:
            raise RuntimeError("Production-source harness compilation failed")
        environment = dict(os.environ)
        if sanitizers != "none":
            environment["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
            environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        result["sanitizers"]["runtimeOptions"] = {
            name: environment.get(name) for name in ("ASAN_OPTIONS", "UBSAN_OPTIONS")
        }
        executed = subprocess.run([str(binary), seed_text, cases_text],
                                  env=environment, capture_output=True,
                                  text=True, timeout=30)
        result["executionExitCode"] = executed.returncode
        result["sanitizerDiagnostics"] = executed.stderr
        if not executed.stdout:
            raise RuntimeError("Parser fixture produced no JSON; inspect execution/sanitizer diagnostics")
        properties = json.loads(executed.stdout)
        result.update(properties)
        result["passed"] = executed.returncode == 0 and properties["strict"]["failed"] == 0
        if executed.stderr:
            result["passed"] = False
            result["error"] = "Unexpected execution/sanitizer diagnostics"
except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
    result["passed"] = False
    result["error"] = str(error)
result["sourceUnchangedDuringTest"] = sha256(transport) == before
result["passed"] = result.get("passed", False) and result["sourceUnchangedDuringTest"]
result["finishedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
print(json.dumps(result, indent=2))
sys.exit(0 if result["passed"] else 1)
PY
