#!/usr/bin/env bash
# Real receive-side frame parser, ASan+UBSan; no network or production patches.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source_dir=$(cd -- "$script_dir/../.." && pwd -P)
objects_dir=
sanitizers=address,undefined
usage() {
    printf '%s\n' 'Usage: quic-frames.sh [--source DIR] [--objs DIR] [--no-sanitize]' \
        'JSON to stdout. Default ASan+UBSan; LSan disabled. No network.'
}
while (($#)); do
    case "$1" in
        --source|--objs)
            if (($# < 2)); then usage >&2; exit 2; fi
            if [[ $1 == --source ]]; then source_dir=$2; else objects_dir=$2; fi
            shift 2 ;;
        --no-sanitize) sanitizers=none; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
source_dir=$(cd -- "$source_dir" && pwd -P)
if [[ -z $objects_dir ]]; then objects_dir=$source_dir/x10/.build/objs; fi
objects_dir=$(cd -- "$objects_dir" && pwd -P)
python3 - "$source_dir" "$objects_dir" "$script_dir" "$sanitizers" "${CC:-cc}" <<'PY'
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

source, objects, harness = map(Path, sys.argv[1:4])
sanitizers, compiler = sys.argv[4:]
stamp = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
transport = source / 'src/event/quic/ngx_event_quic_transport.c'
test = harness / 'quic-frames.c'
files = [transport, source / 'src/event/quic/ngx_event_quic_transport.h',
         source / 'src/event/quic/ngx_event_quic_connection.h']
generated = ['ngx_auto_config.h', 'ngx_auto_headers.h', 'ngx_modules.c']
result = {'schemaVersion': 1, 'suite': 'quic-frame-boundaries', 'startedAt': stamp(),
          'passed': False, 'networkUsed': False, 'seed': 9000,
          'randomInputs': 4096, 'source': 'src/event/quic/ngx_event_quic_transport.c',
          'limitations': [
              'Six bounded properties and related inputs are not independent protocol/security tests.',
              'Parsing only: ACK arithmetic, stream flow/final-size and connection state handlers are outside this fixture.',
              'Nonminimal frame-type rejection is receiver MAY policy; observations are not strict failures.',
              '64-bit Linux profile only; no 32-bit, packet protection, handshake, network or interoperability proof.',
              'ASan and UBSan check this corpus; LeakSanitizer is disabled and memory leaks are unverified.']}
try:
    before = {str(p.relative_to(source)): sha(p) for p in files}
    generated_before = {name: sha(objects / name) for name in generated}
    result.update(sourceSha256=sha(transport), sourceFilesSha256=before,
                  sourceCheckout=source.name, harnessSha256=sha(test),
                  generatedConfigSha256=generated_before['ngx_auto_config.h'],
                  generatedFilesSha256=generated_before)
    revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=source,
                              capture_output=True, text=True, timeout=5)
    result['checkoutRevision'] = revision.stdout.strip() if revision.returncode == 0 else None
    flags = ['-std=c99', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
             '-Wno-unused-parameter', '-ffunction-sections', '-fdata-sections']
    if sanitizers != 'none':
        flags += ['-fsanitize=' + sanitizers, '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
    result.update(compilerExecutable=compiler, compilerFlags=flags,
                  compiler=subprocess.run([compiler, '--version'], capture_output=True,
                                          text=True, timeout=5, check=True).stdout.splitlines()[0],
                  sanitizers={'enabled': [] if sanitizers == 'none' else sanitizers.split(','),
                              'leakDetection': False})
    with tempfile.TemporaryDirectory(prefix='x10-quic-frames-') as temporary:
        binary = Path(temporary) / 'quic-frames'
        argv = [compiler, *flags, '-DNGX_QUIC_TRANSPORT_SOURCE="' + str(transport) + '"']
        for name in ['src/core', 'src/event', 'src/event/modules', 'src/event/quic', 'src/os/unix']:
            argv += ['-I', str(source / name)]
        argv += ['-I', str(objects), str(test), '-Wl,--gc-sections', '-o', str(binary)]
        built = subprocess.run(argv, capture_output=True, text=True, timeout=90)
        result.update(compileExitCode=built.returncode, compilerDiagnostics=built.stderr)
        if built.returncode:
            raise RuntimeError('Production translation-unit harness compilation failed')
        env = dict(os.environ)
        if sanitizers != 'none':
            env.update(ASAN_OPTIONS='detect_leaks=0:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        result['sanitizers']['runtimeOptions'] = {key: env.get(key) for key in ['ASAN_OPTIONS', 'UBSAN_OPTIONS']}
        run = subprocess.run([str(binary)], env=env, capture_output=True, text=True, timeout=30)
        result.update(executionExitCode=run.returncode, sanitizerDiagnostics=run.stderr)
        if not run.stdout:
            raise RuntimeError('No JSON produced by parser harness')
        result.update(json.loads(run.stdout))
        result['passed'] = run.returncode == 0 and result['strict']['failed'] == 0 and not run.stderr
    result['temporaryRootRemoved'] = not Path(temporary).exists()
except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
    result['error'] = str(error)
    result['passed'] = False
try:
    result['sourceUnchangedDuringTest'] = before == {str(p.relative_to(source)): sha(p) for p in files}
    result['generatedFilesUnchangedDuringTest'] = generated_before == {name: sha(objects / name) for name in generated}
except (OSError, NameError):
    result['sourceUnchangedDuringTest'] = False
    result['generatedFilesUnchangedDuringTest'] = False
result['passed'] = (result['passed'] and result['sourceUnchangedDuringTest']
                    and result['generatedFilesUnchangedDuringTest'] and result.get('temporaryRootRemoved') is True)
result['finishedAt'] = stamp()
print(json.dumps(result, indent=2))
sys.exit(0 if result['passed'] else 1)
PY
