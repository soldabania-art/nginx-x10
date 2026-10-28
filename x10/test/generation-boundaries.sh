#!/usr/bin/env bash
# Actual native generation code and JSON renderer, with ASan/UBSan. No network.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
python3 - "$script_dir" "$@" <<'PY'
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

harness = Path(sys.argv[1])
parser = argparse.ArgumentParser(description='Actual generation counter/JSON boundaries under ASan/UBSan; no network.')
parser.add_argument('--source', type=Path, default=harness.parent.parent)
parser.add_argument('--objs', type=Path)
args = parser.parse_args(sys.argv[2:])
source = args.source.resolve(strict=True)
objects = (args.objs or source/'x10/.build/objs').resolve(strict=True)
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
stamp = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
class Interrupted(RuntimeError): pass
interrupted = None
active = None

def stop(number, _frame):
    global interrupted
    interrupted = signal.Signals(number).name
    raise Interrupted('Generation boundary fixture interrupted by '+interrupted)
for sig in (signal.SIGINT, signal.SIGTERM): signal.signal(sig, stop)

def run(argv, timeout, env=None):
    global active
    active = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, start_new_session=True, env=env)
    child = active
    try:
        out, err = child.communicate(timeout=timeout)
        return child.returncode, out, err
    finally:
        try: os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        child.communicate(timeout=3)
        active = None

files = ['src/os/unix/ngx_control.c','src/os/unix/ngx_control.h',
         'src/os/unix/ngx_process.c','src/os/unix/ngx_process_cycle.c',
         'src/core/ngx_data.c','src/core/ngx_string.c','src/core/ngx_json.c',
         'src/core/ngx_palloc.c','src/core/ngx_buf.c','src/os/unix/ngx_alloc.c']
core = ['src/core/ngx_string.c','src/core/ngx_data.c','src/core/ngx_json.c',
        'src/core/ngx_palloc.c','src/core/ngx_buf.c','src/os/unix/ngx_alloc.c']
generated_names = ['ngx_auto_config.h','ngx_auto_headers.h','ngx_modules.c']
result = {'schemaVersion':1,'suite':'native-generation-boundaries','startedAt':stamp(),
          'passed':False,'networkUsed':False,'tests':[],
          'limitations':['Actual production counter and JSON-rendering code; send capture and logging are the only stubs.',
                        'Direct counter controls do not execute fork, scheduler ordering, worker initialization or listener closure.',
                        '64-bit Linux profile tested; decimal width checks are not a 32-bit build claim.',
                        'ASan/UBSan corpus; LeakSanitizer is disabled and leaks are not certified.']}
before = generated = None
temporary = None
try:
    before = {p:sha(source/p) for p in files}
    generated = {n:sha(objects/n) for n in generated_names}
    if not re.search(r'^#define\s+NGX_CONTROL_API\s+1\s*$',(objects/'ngx_auto_config.h').read_text(),re.M):
        raise RuntimeError('Generated profile must enable the native control API')
    test = harness/'generation-boundaries.c'
    result.update(sourceFilesSha256=before, sourceSha256=before[files[0]],
                  harnessSha256=sha(test), runnerSha256=sha(harness/'generation-boundaries.sh'),
                  generatedFilesSha256=generated, generatedConfigSha256=generated['ngx_auto_config.h'])
    flags = ['-std=c99','-O1','-g','-Wall','-Wextra','-Werror',
             '-Wno-unused-parameter','-Wno-unused-function','-ffunction-sections','-fdata-sections',
             '-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer']
    compiler = os.environ.get('CC','cc')
    code, out, err = run([compiler,'--version'],10)
    if code: raise RuntimeError('Compiler identity failed: '+err[:4096])
    result.update(compiler=out.splitlines()[0],compilerExecutable=compiler,compilerFlags=flags,
                  sanitizers={'enabled':['address','undefined'],'leakDetection':False})
    with tempfile.TemporaryDirectory(prefix='x10-generation-boundaries-') as temporary:
        binary = Path(temporary)/'generation-boundaries'
        argv = [compiler,*flags,'-DNGX_CONTROL_SOURCE="'+str(source/files[0])+'"']
        for directory in ['src/core','src/event','src/event/modules','src/event/quic','src/os/unix']:
            argv += ['-I',str(source/directory)]
        argv += ['-I',str(objects),str(test),*[str(source/p) for p in core],'-Wl,--gc-sections','-o',str(binary)]
        result['compileArgv'] = argv
        code, out, err = run(argv,90)
        result.update(compileExitCode=code,compilerDiagnostics=err)
        if code: raise RuntimeError('Production generation harness compilation failed')
        result['binarySha256'] = sha(binary)
        env = dict(os.environ,ASAN_OPTIONS='detect_leaks=0:halt_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        code, out, err = run([str(binary)],15,env)
        result.update(executionExitCode=code,sanitizerDiagnostics=err)
        if code or err: raise RuntimeError('Production generation harness execution or sanitizer failed')
        if len(out.encode()) > 2*1024*1024: raise RuntimeError('Counter output exceeds bounded profile')
        records = {}
        for line in out.splitlines():
            name,body = line.split('\t',1)
            if name in records: raise RuntimeError('Duplicate counter case')
            records[name] = json.loads(body)
        if len(records) != 18: raise RuntimeError('Expected 18 actual rendered counter records')
        result['responses'] = records
        def check(name, condition):
            result['tests'].append({'name':name,'passed':bool(condition)})
            if not condition: raise AssertionError(name)
        def p(name,slot=0): return next(x for x in records[name]['processes'] if x['slot']==slot)
        def allnull(name): return records[name]['current_generation'] is None and all(x['generation'] is None and x['birth'] is None for x in records[name]['processes'])
        check('initial-generation-and-distinct-births',records['initial-two-workers']['current_generation']=='1' and [x['birth'] for x in records['initial-two-workers']['processes']]==['1','2'])
        check('successful-cycle-commits-advance-before-spawn',records['two-cycle-commits-before-spawn']['current_generation']=='3' and all(x['generation']=='1' for x in records['two-cycle-commits-before-spawn']['processes']))
        check('respawn-overwrites-slot-with-current-generation-and-new-birth',p('respawn-overwrites-slot')['pid']==103 and p('respawn-overwrites-slot')['generation']=='3' and p('respawn-overwrites-slot')['birth']=='3' and p('respawn-overwrites-slot',1)['birth']=='2')
        check('same-pid-callback-gets-new-birth',p('same-pid-new-birth')['pid']==103 and p('same-pid-new-birth')['birth']=='4')
        check('stale-slot-pid-is-unclassified',not records['stale-slot-pid']['available'] and records['stale-slot-pid']['reason']=='unclassified_process' and p('stale-slot-pid')['generation'] is None and p('stale-slot-pid')['birth'] is None)
        check('unknown-cycle-keeps-known-current-but-nulls-process-generation',not records['unclassified-cycle']['available'] and records['unclassified-cycle']['current_generation']=='1' and p('unclassified-cycle')['generation'] is None and p('unclassified-cycle')['birth']=='1')
        check('detached-process-excluded-without-consuming-birth',records['detached-excluded']['excluded_detached']==1 and len(records['detached-excluded']['processes'])==1 and records['detached-excluded']['available'])
        check('invalid-slot-allocation-is-noop',records['invalid-slot-noop']==records['detached-excluded'])
        check('wide-identities-are-exact-decimal-strings',records['wide-decimal-identities']['current_generation']=='4294967420' and p('wide-decimal-identities')['generation']=='4294967420' and p('wide-decimal-identities')['birth']=='9007199254741104')
        check('last-generation-uint64-value-is-exact',records['last-generation-value']['available'] and records['last-generation-value']['current_generation']=='18446744073709551615' and p('last-generation-value')['generation']=='18446744073709551615')
        check('generation-exhaustion-nulls-all-identities',not records['generation-exhausted']['available'] and records['generation-exhausted']['reason']=='counter_exhausted' and allnull('generation-exhausted'))
        check('generation-exhaustion-remains-latched',records['generation-exhaustion-latched']['reason']=='counter_exhausted' and allnull('generation-exhaustion-latched'))
        check('last-birth-uint64-value-is-exact',records['last-birth-value']['available'] and p('last-birth-value')['birth']=='18446744073709551615')
        check('birth-exhaustion-nulls-all-identities',not records['birth-exhausted']['available'] and records['birth-exhausted']['reason']=='counter_exhausted' and allnull('birth-exhausted'))
        check('birth-exhaustion-remains-latched',records['birth-exhaustion-latched']['reason']=='counter_exhausted' and allnull('birth-exhaustion-latched'))
        check('uninitialized-diagnostics-explicitly-unavailable',not records['uninitialized']['available'] and records['uninitialized']['reason']=='uninitialized' and allnull('uninitialized'))
        check('inactive-hooks-do-not-change-state',records['inactive-hooks-noop']['current_generation']=='1' and p('inactive-hooks-noop')['pid']==116 and p('inactive-hooks-noop')['birth']=='1')
        check('new-master-start-resets-scoped-counters',records['master-start-reset']['current_generation']=='1' and records['master-start-reset']['available'] and records['master-start-reset']['processes']==[])
        check('all-responses-have-master-scope-and-pid',all(x['scope']=='master-process' and x['master_pid']==12345 for x in records.values()))
        check('json-flags-retain-boolean-types',all(isinstance(x['available'],bool) and isinstance(x['excluded_detached'],int) and all(isinstance(y['exiting'],bool) and isinstance(y['exited'],bool) for y in x['processes']) for x in records.values()))
        result['passed'] = len(result['tests'])==20 and all(t['passed'] for t in result['tests'])
except (OSError,RuntimeError,AssertionError,ValueError,StopIteration,subprocess.SubprocessError) as error:
    result['error'] = str(error)
    result['passed'] = False
finally:
    if active is not None:
        try: os.killpg(active.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        active.communicate(timeout=3)
        active = None
try:
    result['sourceUnchangedDuringTest'] = before is not None and before=={p:sha(source/p) for p in files}
    result['generatedFilesUnchangedDuringTest'] = generated is not None and generated=={n:sha(objects/n) for n in generated_names}
    result['harnessUnchangedDuringTest'] = result.get('harnessSha256')==sha(harness/'generation-boundaries.c')
    result['runnerUnchangedDuringTest'] = result.get('runnerSha256')==sha(harness/'generation-boundaries.sh')
except OSError:
    result['sourceUnchangedDuringTest'] = False
result.update(temporaryRootRemoved=temporary is not None and not Path(temporary).exists(),
              activeChildren=0 if active is None else 1,interrupted=interrupted,finishedAt=stamp())
result['passed'] = bool(result['passed'] and not interrupted and result['sourceUnchangedDuringTest']
                        and result.get('generatedFilesUnchangedDuringTest') and result.get('harnessUnchangedDuringTest')
                        and result.get('runnerUnchangedDuringTest') and result['temporaryRootRemoved'] and result['activeChildren']==0)
print(json.dumps(result,indent=2))
sys.exit(0 if result['passed'] else 1)
PY
