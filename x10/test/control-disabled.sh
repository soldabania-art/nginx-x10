#!/usr/bin/env bash
# Verify the Linux profile without the optional native control API.
# Run after x10/build.sh; configure jobs must not overlap (root Makefile).
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source_dir=$(cd -- "$script_dir/../.." && pwd -P)
python3 - "$source_dir" "$@" <<'PY'
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

source = Path(sys.argv[1])
parser = argparse.ArgumentParser(description='Build and verify the current Linux profile without --with-control-api. Run serially after x10/build.sh.')
parser.add_argument('--output', type=Path)
args = parser.parse_args(sys.argv[2:])
state = source / 'x10/.build'
objects = state / 'objs-control-disabled'
runtime = state / 'runtime-control-disabled'
logs = state / 'control-disabled'
manifest_path = state / 'manifest.json'
root_makefile = source / 'Makefile'
active = None
interrupted = None
report = {'schemaVersion': 1, 'suite': 'native-control-disabled-build',
          'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'success': False, 'jobs': 2, 'installed': False, 'tests': [], 'commands': [],
          'limitations': ['Linux profile only; not a full compiler/platform matrix.',
                         'Invalid-option rejection and absent endpoint path are checked; no syscall tracing or syscall-absence proof.',
                         'The alternative build is not installed and starts no native service.']}
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

class Cancelled(RuntimeError):
    pass

def cancel(number, _frame):
    global interrupted
    interrupted = signal.Signals(number).name
    raise Cancelled('Interrupted by ' + interrupted)

for sig in (signal.SIGINT, signal.SIGTERM):
    signal.signal(sig, cancel)

def stop(child):
    if child is None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=0.75)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait(timeout=2)

def command(argv, name, timeout):
    global active
    log = logs / (name + '.log')
    entry = {'argv': list(map(str, argv)), 'cwd': str(source), 'timeoutSeconds': timeout,
             'log': str(log), 'outputLimitBytes': 8 * 1024 * 1024}
    report['commands'].append(entry)
    started = time.monotonic()
    collected = bytearray()
    active = subprocess.Popen(entry['argv'], cwd=source, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, start_new_session=True)
    child = active
    try:
        with selectors.DefaultSelector() as selector, log.open('wb') as stream:
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if interrupted:
                    raise Cancelled('Interrupted by ' + interrupted)
                if time.monotonic() - started > timeout:
                    raise RuntimeError(name + ' exceeded its deadline')
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if entry.get('outputBytes', 0) + len(chunk) > entry['outputLimitBytes']:
                        raise RuntimeError(name + ' exceeded its output limit')
                    entry['outputBytes'] = entry.get('outputBytes', 0) + len(chunk)
                    stream.write(chunk)
                    collected.extend(chunk)
                    if len(collected) > 16384:
                        del collected[:-16384]
            entry['exitCode'] = child.wait(timeout=max(0.01, timeout - (time.monotonic() - started)))
    finally:
        stop(child)
        child.stdout.close()
        active = None
        entry['elapsedMs'] = round((time.monotonic() - started) * 1000)
        entry['logSha256'] = sha(log) if log.exists() else None
        entry['outputTail'] = collected.decode(errors='replace')
        entry.setdefault('exitCode', child.returncode)
    return entry

def require(value, text):
    if not value:
        raise RuntimeError(text)

def snapshot_sources(pin):
    tracked = subprocess.run(['git', 'ls-files', '--', 'src', 'auto', 'conf'], cwd=source,
                             capture_output=True, text=True, check=True, timeout=10).stdout.splitlines()
    untracked = subprocess.run(['git', 'ls-files', '--others', '--exclude-standard', '--', 'src', 'auto', 'conf'],
                               cwd=source, capture_output=True, text=True, check=True, timeout=10).stdout.splitlines()
    diff = subprocess.run(['git', 'diff', '--binary', pin, '--', 'src', 'auto', 'conf'], cwd=source,
                          capture_output=True, check=True, timeout=10).stdout
    require(not untracked, 'Untracked native inputs prevent source consistency verification')
    return {'sourceDiffSha256': hashlib.sha256(diff).hexdigest(),
            'filesSha256': {name: sha(source / name) for name in tracked}}

def file_record(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode), 'Expected regular file: ' + str(path))
    return {'sha256': sha(path), 'bytes': info.st_size, 'mode': format(stat.S_IMODE(info.st_mode), '04o')}

before = default_files = makefile_before = None
temporary = None
try:
    require(sys.platform == 'linux', 'Linux is required')
    state.mkdir(exist_ok=True)
    logs.mkdir(exist_ok=True)
    manifest = json.loads(manifest_path.read_text())
    require(manifest.get('status') == 'built', 'Build the current default profile first with bash x10/build.sh')
    require(manifest['configureArgv'][:2] == ['sh', 'auto/configure'], 'Unexpected default configure command')
    require(manifest['configureArgv'].count('--with-control-api') == 1, 'Default profile must explicitly enable the control API')
    pin = manifest['upstreamRevision']
    before = snapshot_sources(pin)
    require(before['sourceDiffSha256'] == manifest['sourceDiffSha256'], 'Native sources changed after the default build')
    default_binary = Path(manifest['binary']['path'])
    default_generated = [Path(manifest['makeArgv'][2]).parent / name for name in ('ngx_auto_config.h', 'ngx_auto_headers.h', 'ngx_modules.c')]
    default_files = {str(p): file_record(p) for p in [manifest_path, default_binary, *default_generated]}
    require(default_files[str(default_binary)]['sha256'] == manifest['binary']['sha256'], 'Default binary differs from its manifest')
    require(os.access(default_binary, os.X_OK), 'Default binary is not executable')
    report['defaultBuild'] = {'manifestPath': str(manifest_path), 'manifestSha256': sha(manifest_path),
                              'binary': str(default_binary), 'binarySha256': sha(default_binary)}
    report['source'] = before
    report['harnessSha256'] = sha(source / 'x10/test/control-disabled.sh')
    configure = ['--builddir=' + str(objects) if x.startswith('--builddir=') else
                 '--prefix=' + str(runtime) if x.startswith('--prefix=') else x
                 for x in manifest['configureArgv'][2:] if x != '--with-control-api']
    report['configureArgv'] = ['sh', 'auto/configure', *configure]
    report['featureDifference'] = ['--with-control-api removed; builddir/prefix changed only']
    require(root_makefile.is_file() and not root_makefile.is_symlink(), 'Expected a regular root Makefile to preserve')
    makefile_before = (root_makefile.read_bytes(), stat.S_IMODE(root_makefile.stat().st_mode))
    if objects.exists():
        require(objects.is_dir() and not objects.is_symlink(), 'Alternative objects path must be a directory, not a symlink')
        shutil.rmtree(objects)
    configure_result = command(report['configureArgv'], 'configure', 120)
    require(configure_result['exitCode'] == 0, 'Control-disabled configure failed')
    built = command(['make', '-f', str(objects / 'Makefile'), '-j2'], 'build', 240)
    require(built['exitCode'] == 0, 'Control-disabled compilation failed')
    report['tests'].append({'name': 'feature-disabled-configure-and-compile', 'status': 'passed'})
    config = (objects / 'ngx_auto_config.h').read_text()
    definitions = re.findall(r'^#define\s+NGX_CONTROL_API\s+([^\n]+)', config, re.M)
    require(not definitions or definitions == ['0'], 'Control API macro unexpectedly enabled')
    require(not list(objects.rglob('ngx_control.o')), 'Control API object unexpectedly compiled')
    require('src/os/unix/ngx_control.c' not in (objects / 'Makefile').read_text(), 'Control implementation included in the alternative Makefile')
    report['controlMacroDefinitions'] = definitions
    report['tests'].append({'name': 'feature-macro-and-control-object-absent', 'status': 'passed'})
    binary = objects / 'nginx'
    report['binary'] = {'path': str(binary), **file_record(binary)}
    require(os.access(binary, os.X_OK), 'Alternative binary is not executable')
    version = command([str(binary), '-V'], 'version', 5)
    require(version['exitCode'] == 0 and '--with-control-api' not in version['outputTail'], 'Alternative binary still advertises control support')
    actual_args = re.search(r'^configure arguments: (.*)$', version['outputTail'], re.M)
    import shlex
    require(actual_args is not None and shlex.split(actual_args[1]) == configure, 'Binary configure profile differs from requested profile')
    report['nginxVersionOutput'] = version['outputTail'].strip()
    makefile = (objects / 'Makefile').read_text()
    compiler = re.search(r'^CC\s*=\s*(.*)$', makefile, re.M).group(1).strip()
    flags = re.search(r'^CFLAGS\s*=\s*(.*)$', makefile, re.M).group(1).strip()
    require(compiler == manifest['compiler'] and flags == manifest['compilerFlags'], 'Compiler profile changed')
    report['compiler'] = {'command': compiler, 'flags': flags,
                          'version': command([*shlex.split(compiler), '--version'], 'compiler', 5)['outputTail'].splitlines()[0]}
    modules_text = (objects / 'ngx_modules.c').read_text()
    array = re.search(r'ngx_module_t\s*\*ngx_modules\[\]\s*=\s*\{(.*?)\};', modules_text, re.S)
    modules = re.findall(r'&([A-Za-z0-9_]+)', array.group(1))
    require(modules == manifest['compiledModules'], 'Compiled module list changed beyond optional control core code')
    report['compiledModules'] = modules
    report['generatedFiles'] = {name: file_record(objects / name) for name in ('ngx_auto_config.h', 'ngx_auto_headers.h', 'ngx_modules.c')}
    report['tests'].append({'name': 'version-compiler-and-module-profile-match', 'status': 'passed'})
    temporary = Path(tempfile.mkdtemp(prefix='x10-control-disabled-'))
    temporary.chmod(0o700)
    fifo = temporary / 'must-not-read.conf'
    os.mkfifo(fifo, 0o600)
    endpoint = temporary / 'control.sock'
    rejected = command([str(binary), '-l', 'unix:' + str(endpoint), '-p', str(temporary) + '/', '-c', str(fifo)], 'disabled-option', 3)
    require(rejected['exitCode'] == 1 and rejected['outputTail'].strip() == 'nginx: invalid option: "l"', 'Expected immediate disabled -l option rejection')
    require(not endpoint.exists() and sorted(p.name for p in temporary.iterdir()) == [fifo.name], 'Rejected option left endpoint or runtime files')
    report['optionRejection'] = {'exitCode': rejected['exitCode'], 'diagnostic': rejected['outputTail'].strip(),
                                 'endpointPathCreated': False, 'unopenedConfigFifo': str(fifo),
                                 'scope': 'Option parsing rejects before configuration initialization; no syscall tracing claim.'}
    report['tests'].append({'name': 'disabled-listen-option-rejected-before-config-read', 'status': 'passed'})
    report['success'] = True
except BaseException as error:
    report['error'] = type(error).__name__ + ': ' + str(error)
finally:
    cleanup = {'activeChild': False, 'temporaryRootRemoved': temporary is None, 'rootMakefileRestored': False, 'errors': []}
    try:
        if active is not None:
            stop(active)
        if temporary is not None:
            shutil.rmtree(temporary)
            cleanup['temporaryRootRemoved'] = not temporary.exists()
        if makefile_before is not None:
            restore = root_makefile.with_name('Makefile.x10-control-disabled-' + str(os.getpid()))
            restore.write_bytes(makefile_before[0])
            restore.chmod(makefile_before[1])
            restore.replace(root_makefile)
            cleanup['rootMakefileRestored'] = (root_makefile.read_bytes(), stat.S_IMODE(root_makefile.stat().st_mode)) == makefile_before
        if before is not None:
            report['sourceUnchangedDuringTest'] = snapshot_sources(pin) == before
        if default_files is not None:
            report['defaultBuildUnchangedDuringTest'] = all(file_record(Path(p)) == value for p, value in default_files.items())
        report['harnessUnchangedDuringTest'] = report.get('harnessSha256') == sha(source / 'x10/test/control-disabled.sh')
    except BaseException as error:
        cleanup['errors'].append(type(error).__name__ + ': ' + str(error))
    report['cleanup'] = cleanup
    report['interruptedSignal'] = interrupted
    report['success'] = (report['success'] and not interrupted and not cleanup['errors'] and cleanup['temporaryRootRemoved']
                         and cleanup['rootMakefileRestored'] and report.get('sourceUnchangedDuringTest') is True
                         and report.get('defaultBuildUnchangedDuringTest') is True and report.get('harnessUnchangedDuringTest') is True)
    report['finishedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    text = json.dumps(report, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')
sys.exit(0 if report['success'] else 1)
PY
