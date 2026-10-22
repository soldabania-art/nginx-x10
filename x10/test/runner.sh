#!/usr/bin/env bash
# Compile the selected checkout's parser, using its generated NGINX headers.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source_dir=$(cd -- "$script_dir/../.." && pwd -P)
objects_dir=

usage() {
    printf '%s\n' \
      'Usage: x10/test/runner.sh [--source DIR] [--objs DIR]' \
      '  --source DIR  Checkout whose real transport.c is included.' \
      '  --objs DIR    Existing generated nginx build headers (no configure).' \
      'Prints JSON: 11 strict assertions plus 2 deferred duplicate observations.' \
      'Exits 1 on any strict mismatch; duplicate SHOULD policy does not fail strict.'
}

while (($#)); do
    case "$1" in
        --source|--objs)
            if (($# < 2)); then usage >&2; exit 2; fi
            if [[ $1 == --source ]]; then source_dir=$2; else objects_dir=$2; fi
            shift 2 ;;
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
transport_source=$source_dir/src/event/quic/ngx_event_quic_transport.c
if [[ ! -f $transport_source ]]; then
    printf '%s\n' 'Selected source has no QUIC transport parser.' >&2
    exit 2
fi

test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/nginx-x10-quic-parser.XXXXXXXX")
trap 'rm -rf -- "$test_tmp"' EXIT
read -r source_sha256 ignored < <(sha256sum -- "$transport_source")

"${CC:-cc}" -std=c99 -O1 -g -Wall -Wextra -Werror -Wno-unused-parameter \
    -ffunction-sections -fdata-sections \
    "-DNGX_QUIC_TRANSPORT_SOURCE=\"$transport_source\"" \
    -I "$source_dir/src/core" -I "$source_dir/src/event" \
    -I "$source_dir/src/event/modules" -I "$source_dir/src/event/quic" \
    -I "$source_dir/src/os/unix" -I "$objects_dir" \
    "$script_dir/quic-transport.c" -Wl,--gc-sections \
    -o "$test_tmp/quic-transport"

test_status=0
"$test_tmp/quic-transport" > "$test_tmp/results.json" || test_status=$?
python3 - "$transport_source" "$objects_dir" "$source_sha256" \
    "$test_tmp/results.json" "$test_status" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sys

source, objects, before_hash, result_file, status = sys.argv[1:]
result = json.loads(Path(result_file).read_text())
after_hash = hashlib.sha256(Path(source).read_bytes()).hexdigest()
source_path = Path(source)
checkout = source_path.parents[3]
version = re.search(r'#define\s+NGINX_VERSION\s+"([^"]+)"',
                    (checkout / 'src/core/nginx.h').read_text()).group(1)
config_hash = hashlib.sha256((Path(objects) / 'ngx_auto_config.h').read_bytes()).hexdigest()
result.update(source='src/event/quic/ngx_event_quic_transport.c',
              sourceCheckout=checkout.name, nginxVersion=version,
              generatedConfigSha256=config_hash, sourceSha256=before_hash,
              sourceUnchangedDuringTest=after_hash == before_hash,
              strictExitCode=int(status), networkUsed=False)
print(json.dumps(result, indent=2))
if after_hash != before_hash:
    print('Source changed during compilation/test; rerun required.', file=sys.stderr)
    sys.exit(2)
PY
exit "$test_status"
