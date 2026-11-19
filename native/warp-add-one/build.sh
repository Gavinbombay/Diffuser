#!/usr/bin/env bash
# Offline build-only target. Never launches the helper.
set -euo pipefail
umask 077
here=$(realpath "$(dirname "$0")")
out=${1:?provide a fresh absolute output directory}
[[ $# == 1 && $out == /* ]]
export LC_ALL=C
mapfile -t pins < <(python3 - "$here" <<'PY'
import hashlib, json, pathlib, sys
here = pathlib.Path(sys.argv[1])
prov = json.loads((here / 'PROVENANCE.json').read_text())
lock = json.loads((here / 'TOOLCHAIN-INPUTS.json').read_text())
files = lock['host_inputs']
for name, info in sorted(files.items()):
    path = pathlib.Path(name)
    assert str(path.resolve(strict=True)) == info['realpath'], name
    with path.open('rb') as f:
        assert hashlib.file_digest(f, 'sha256').hexdigest() == info['sha256'], name
print(prov['composition_sha256'])
print(prov['artifact_sha256'])
PY
)
[[ ${#pins[@]} == 2 ]]
printf '%s  %s\n' "${pins[0]}" "$here/add_one.cpp" | sha256sum --strict -c -
mkdir -- "$out"
/usr/bin/g++ -std=c++17 -O2 -Wall -Wextra -Werror -pedantic -fPIE -pie \
    -Wl,-z,relro,-z,now "$here/add_one.cpp" -ldl -o "$out/unverified"
printf '%s  %s\n' "${pins[1]}" "$out/unverified" | sha256sum --strict -c -
chmod 0400 "$out/unverified"
mv -T -- "$out/unverified" "$out/warp-add-one-helper.elf"
sha256sum "$out/warp-add-one-helper.elf"
readelf -W -h -d -V "$out/warp-add-one-helper.elf"
