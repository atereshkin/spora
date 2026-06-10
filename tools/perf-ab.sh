#!/usr/bin/env bash
# perf-ab.sh — A/B perf comparison: current working tree vs a base git ref.
#
# Usage: tools/perf-ab.sh <base-ref> [iterations]     (default 3 iterations)
#
# LIMITATION: <base-ref> must already contain the perf suite
# (spora-lab/tests/perf.rs) — the comparison is meaningful from the commit
# that introduced it onward. Older refs have no perf test binary to build.
#
# Method: builds the perf test binary in BOTH trees up front (the base ref in
# a throwaway git worktree under /tmp with its own target dir), then runs the
# two binaries in ALTERNATION with the within-pair order flipping each
# iteration (base,current / current,base / ... — ABBA): plain ABAB cancels
# slow drift between sides but always runs base first within a pair, so
# monotonic drift (thermal ramp, first-run module loading) biases one slot;
# ABBA cancels linear drift too. Each run writes a metrics JSON via
# SPORA_LAB_PERF_JSON; perf-diff compares the per-metric MEDIANS of the two
# sides at the end, gating each metric at max(--tolerance, its noise_pct).

set -euo pipefail

ref="${1:?usage: tools/perf-ab.sh <base-ref> [iterations]}"
iters="${2:-3}"
if ! [[ "$iters" =~ ^[0-9]+$ ]] || (( iters < 1 )); then
    echo "error: iterations must be a positive integer, got '$iters'" >&2
    exit 2
fi

# A stray baseline gate from the developer's shell must not fail (or even
# run inside) the A/B iterations — A/B is its own comparison.
unset SPORA_LAB_PERF_BASELINE SPORA_LAB_PERF_TOLERANCE

root="$(git rev-parse --show-toplevel)"
worktree="$(mktemp -d /tmp/spora-perf-ab-tree.XXXXXX)"
out="$(mktemp -d /tmp/spora-perf-ab-json.XXXXXX)"

cleanup() {
    git -C "$root" worktree remove --force "$worktree" 2>/dev/null || true
    rm -rf "$worktree" "$out"
}
trap cleanup EXIT

# mktemp created the dir; worktree add wants to create it itself.
rmdir "$worktree"
echo "== preparing base worktree for $ref =="
git -C "$root" worktree add --detach "$worktree" "$ref"

# Build the perf test binary in a tree and print its path, parsed from
# cargo's JSON output (the perf [[test]] artifact lives in target/.../deps/
# as perf-<hash>; the perf-diff bin would match a bare "perf" grep, hence
# the /deps/perf- anchor).
build_perf_bin() {
    local tree="$1" bin log
    log="$(mktemp /tmp/spora-perf-ab-build.XXXXXX.log)"
    bin="$(cd "$tree" && cargo test -p spora-lab --test perf --no-run \
        --message-format=json 2>"$log" \
        | sed -n 's/.*"executable":"\([^"]*\/deps\/perf-[^"]*\)".*/\1/p' \
        | tail -n 1)"
    if [[ -z "$bin" || ! -x "$bin" ]]; then
        echo "error: could not locate the perf test executable for $tree" >&2
        echo "       (does this tree contain spora-lab/tests/perf.rs?)" >&2
        echo "------ cargo output ------" >&2
        cat "$log" >&2
        rm -f "$log"
        return 1
    fi
    rm -f "$log"
    printf '%s\n' "$bin"
}

echo "== building base perf binary ($ref) =="
base_bin="$(build_perf_bin "$worktree")"
echo "== building current perf binary =="
cur_bin="$(build_perf_bin "$root")"

# A silently-skipping lab (no userns etc.) must fail, not produce no JSONs.
export SPORA_LAB=require

run_base() {
    echo "== iteration $1/$iters: base ($ref) =="
    (cd "$worktree" && SPORA_LAB_PERF_JSON="$out/base-$1.json" "$base_bin")
}
run_cur() {
    echo "== iteration $1/$iters: current =="
    (cd "$root" && SPORA_LAB_PERF_JSON="$out/cur-$1.json" "$cur_bin")
}
for i in $(seq 1 "$iters"); do
    if (( i % 2 == 1 )); then
        run_base "$i"; run_cur "$i"
    else
        run_cur "$i"; run_base "$i"
    fi
done

echo "== perf-diff (medians of $iters run(s) per side) =="
(cd "$root" && cargo run -q -p spora-lab --bin perf-diff -- \
    "$out"/base-*.json -- "$out"/cur-*.json)
