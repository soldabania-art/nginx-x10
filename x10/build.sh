#!/usr/bin/env bash
# Build the pinned NGINX X10 Linux profile without installing it.
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: x10/build.sh [--configure-only] [--jobs N]' \
        '  --configure-only  Generate configuration and a manifest; do not compile.' \
        '  --jobs N          Parallel make jobs, 1..64 (default: 2).'
}

jobs=2
configure_only=0
while (($#)); do
    case "$1" in
        --configure-only) configure_only=1; shift ;;
        --jobs)
            if (($# < 2)); then usage >&2; exit 2; fi
            jobs=$2; shift 2 ;;
        --jobs=*) jobs=${1#*=}; shift ;;
        --help|-h) usage; exit 0 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done
case "$jobs" in
    [1-9]|[1-5][0-9]|6[0-4]) ;;
    *) printf '%s\n' '--jobs must be an integer from 1 to 64.' >&2; exit 2 ;;
esac

for program in sh make python3 git cc tee uname; do
    if ! command -v "$program" >/dev/null 2>&1; then
        printf 'Missing prerequisite: %s\n' "$program" >&2
        exit 1
    fi
done
if [[ $(uname -s) != Linux ]]; then
    printf '%s\n' 'This build profile currently supports Linux only.' >&2
    exit 1
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source_dir=$(cd -- "$script_dir/.." && pwd -P)
# The upstream configure scripts and generated Makefile do not escape all paths.
case "$source_dir" in
    *[!A-Za-z0-9_./+-]*)
        printf '%s\n' 'Use a checkout path containing only letters, digits, / . _ + -.' >&2
        exit 1 ;;
esac
cd -- "$source_dir"
state_dir=$script_dir/.build
objects_dir=$state_dir/objs
runtime_dir=$state_dir/runtime
mkdir -p -- "$state_dir"

configure_args=(
    "--builddir=$objects_dir"
    "--prefix=$runtime_dir"
    --with-http_ssl_module
    --with-http_v2_module
    --with-http_v3_module
    --with-stream
    --with-stream_ssl_module
    --with-stream_ssl_preread_module
    --with-mail
    --with-mail_ssl_module
    --with-threads
    --with-file-aio
    --with-http_realip_module
    --with-http_stub_status_module
    --with-http_auth_request_module
    --with-http_addition_module
    --with-http_sub_module
    --with-http_dav_module
    --with-http_slice_module
    --with-http_gunzip_module
    --with-http_gzip_static_module
    --with-compat
    --with-control-api
)

write_manifest() {
    python3 - "$source_dir" "$state_dir" "$1" "$jobs" "${configure_args[@]}" <<'PY'
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys

source, state = map(Path, sys.argv[1:3])
status, jobs = sys.argv[3], int(sys.argv[4])
configure = sys.argv[5:]
objects = state / "objs"
upstream = "148c75678cd4171338c31d4ed4c02411736d5fe9"

def command(argv):
    result = subprocess.run(argv, cwd=source, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"{argv[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()

def write_json(value):
    temporary = state / "manifest.json.tmp"
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(state / "manifest.json")

def identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mode,
            value.st_mtime_ns, value.st_ctime_ns)

generated_files = {}
generated_bytes = {}
generated_identity = {}
try:
    for name in ("ngx_auto_config.h", "ngx_auto_headers.h", "ngx_modules.c"):
        path = objects / name
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o444:
            raise RuntimeError(f"Generated input is not a readable regular file: {path}")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            if identity(before) != identity(os.fstat(stream.fileno())):
                raise RuntimeError(f"Generated input changed while opening it: {path}")
            data = stream.read()
            if identity(before) != identity(os.fstat(stream.fileno())):
                raise RuntimeError(f"Generated input changed while reading it: {path}")
        if identity(before) != identity(path.lstat()):
            raise RuntimeError(f"Generated input changed while verifying it: {path}")
        generated_files[name] = {"sha256": hashlib.sha256(data).hexdigest(),
                                 "bytes": len(data),
                                 "mode": f"{stat.S_IMODE(before.st_mode):04o}"}
        generated_bytes[name] = data
        generated_identity[name] = identity(before)
except (OSError, RuntimeError) as error:
    write_json({"schemaVersion": 1, "profile": "nginx-x10-linux",
                "status": "verification_failed",
                "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "upstreamRevision": upstream, "generatedFiles": generated_files,
                "binary": None,
                "error": {"phase": "generated_inputs", "message": str(error)}})
    print(error, file=sys.stderr)
    sys.exit(1)

source_diff = subprocess.run(
    ["git", "diff", "--binary", upstream, "--", "src", "auto", "conf"],
    cwd=source, capture_output=True, check=True).stdout
modules_text = generated_bytes["ngx_modules.c"].decode()
module_array = re.search(r"ngx_module_t\s*\*ngx_modules\[\]\s*=\s*\{(.*?)\};",
                         modules_text, re.S)
if module_array is None:
    raise RuntimeError("No generated ngx_modules array found")
modules = re.findall(r"&([A-Za-z0-9_]+)", module_array.group(1))
header = (source / "src/core/nginx.h").read_text()
version = re.search(r'#define\s+NGINX_VERSION\s+"([^"]+)"', header).group(1)
makefile = (objects / "Makefile").read_text()
compiler = re.search(r"^CC\s*=\s*(.*)$", makefile, re.M).group(1).strip()
compiler_flags = re.search(r"^CFLAGS\s*=\s*(.*)$", makefile, re.M).group(1).strip()
preprocessor = subprocess.run(
    [*shlex.split(compiler), *shlex.split(compiler_flags), "-E", "-dM",
     "-DPCRE2_CODE_UNIT_WIDTH=8", "-include", "pcre2.h", "-include",
     "openssl/opensslv.h", "-include", "zlib.h", "-x", "c", "-"],
    input="", text=True, capture_output=True, check=True)
macros = dict(re.findall(r"^#define\s+(\w+) ?([^\n]*)$",
                         preprocessor.stdout, re.M))
header_versions = {
    "pcre2": macros["PCRE2_MAJOR"].strip() + "." + macros["PCRE2_MINOR"].strip(),
    "openssl": macros["OPENSSL_VERSION_TEXT"].strip().strip('"'),
    "zlib": macros["ZLIB_VERSION"].strip().strip('"'),
}
packages = {}
if shutil.which("pkg-config"):
    for package in ("libpcre2-8", "openssl", "zlib"):
        result = subprocess.run(["pkg-config", "--modversion", package],
                                text=True, capture_output=True)
        packages[package] = result.stdout.strip() if result.returncode == 0 else None

binary = None
version_output = None
verification_error = None
verification_phase = "binary_verification"
if status == "built":
    path = objects / "nginx"
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111:
            raise RuntimeError(f"Binary is not an executable regular file: {path}")
        if not os.access(path, os.X_OK):
            raise RuntimeError(f"Binary is not executable by the current user: {path}")
        result = subprocess.run([str(path), "-V"], text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError(f"Built nginx -V failed with exit {result.returncode}")
        version_output = result.stderr.strip()
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else None
        if digest is None:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        after = path.lstat()
        if identity(before) != identity(after) or not os.access(path, os.X_OK):
            raise RuntimeError("Binary changed while verifying it")
        binary = {"path": str(path), "sha256": digest, "bytes": after.st_size,
                  "mode": f"{stat.S_IMODE(after.st_mode):04o}", "executable": True}
    except (OSError, RuntimeError) as error:
        status = "verification_failed"
        verification_error = str(error)
        version_output = None

try:
    for name, expected in generated_identity.items():
        if identity((objects / name).lstat()) != expected:
            raise RuntimeError(f"Generated input changed during manifest verification: {name}")
except (OSError, RuntimeError) as error:
    status = "verification_failed"
    verification_error = str(error)
    verification_phase = "generated_inputs"
    binary = None
    version_output = None

manifest = {
    "schemaVersion": 1,
    "profile": "nginx-x10-linux",
    "status": status,
    "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "upstreamRepository": "https://github.com/nginx/nginx",
    "upstreamRevision": upstream,
    "checkoutRevision": command(["git", "rev-parse", "HEAD"]),
    "trackedChanges": command(["git", "diff", "--name-only", "HEAD"]).splitlines(),
    "sourceChangesFromUpstream": command(["git", "diff", "--name-only", upstream,
                                           "--", "src", "auto", "conf"]).splitlines(),
    "sourceDiffSha256": hashlib.sha256(source_diff).hexdigest(),
    "platform": {"system": os.uname().sysname, "release": os.uname().release,
                 "machine": os.uname().machine},
    "nginxVersion": version,
    "configureArgv": ["sh", "auto/configure", *configure],
    "makeArgv": ["make", "-f", str(objects / "Makefile"), f"-j{jobs}"],
    "workingDirectory": str(source),
    "prefix": str(state / "runtime"),
    "compiler": compiler,
    "compilerFlags": compiler_flags,
    "compiledModules": modules,
    "generatedFiles": generated_files,
    "dependencyVersionsFromHeaders": header_versions,
    "dependencyVersionsFromPkgConfig": packages,
    "dependencyVersionNote": "Header versions are from the configured compiler preprocessor; pkg-config is optional package metadata; nginxVersionOutput records binary -V build/runtime information",
    "nginxVersionOutput": version_output,
    "binary": binary,
    "installed": False,
}
if verification_error:
    manifest["error"] = {"phase": verification_phase, "message": verification_error}
write_json(manifest)
if verification_error:
    print(verification_error, file=sys.stderr)
    sys.exit(1)
PY
}

# Never leave an older successful manifest describing a failed new attempt.
rm -f -- "$state_dir/manifest.json"
printf 'Configuring %s\n' "$objects_dir"
sh auto/configure "${configure_args[@]}" 2>&1 | tee "$state_dir/configure.log"
write_manifest configured
if ((configure_only)); then
    printf 'Configured. Manifest: %s\n' "$state_dir/manifest.json"
    exit 0
fi

if ! make -f "$objects_dir/Makefile" "-j$jobs" 2>&1 | tee "$state_dir/build.log"; then
    write_manifest build_failed
    exit 1
fi
write_manifest built
printf 'Built: %s\nManifest: %s\n' "$objects_dir/nginx" "$state_dir/manifest.json"
