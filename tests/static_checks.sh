#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bash -n threatHunt_pcaps.sh

./threatHunt_pcaps.sh --help >/dev/null
./threatHunt_pcaps.sh --version | grep -q '^threatHunt_pcaps.sh '

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
empty_output="$tmp_dir/empty.out"

if ./threatHunt_pcaps.sh -i "$tmp_dir" -o "$tmp_dir/out" >"$empty_output" 2>&1; then
    echo "expected empty input directory to fail" >&2
    exit 1
fi
grep -q 'No .pcap or .pcapng files found' "$empty_output"

echo "static checks passed"
