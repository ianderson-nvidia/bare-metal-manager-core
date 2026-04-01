# Debugging Nix Builds

This document lists commands for inspecting Nix derivations, dependency
graphs, and cache state. Most of these are read-only diagnostic
commands — safe to run any time.

Assumes you're in the workspace root with `flake.nix` present.

## Show a derivation's store path

```sh
nix eval --raw .#carbide-api-container.drvPath
nix eval --raw .#carbide-api.drvPath
nix eval --raw .#deps.drvPath
```

Each prints a `/nix/store/<hash>-<name>.drv` path. If the hash is the
same between two runs, the derivation is identical (fully cached). If
it differs, something about its inputs changed.

The `--raw` flag strips surrounding quotes so the output is pasteable.

## Show derivation contents

```sh
nix derivation show .#carbide-api-container
```

Prints the full JSON of a derivation including env vars, build
inputs, outputs, and the builder script. Useful for verifying that
environment variables (like `KEA_LIB_PATH` or `SQLX_OFFLINE`) made it
into the build.

For the full transitive graph:

```sh
nix derivation show --recursive .#carbide-api-container | jq 'keys'
```

## Check if a derivation is cached locally

```sh
nix path-info .#deps 2>&1 || echo "not yet built"
nix path-info --derivation .#deps
```

`nix path-info` without arguments shows the output path; with
`--derivation` shows the `.drv` path. Failure means the derivation
hasn't been realized in the local store yet.

## Browse a derivation's runtime closure

```sh
nix-store --query --requisites $(nix eval --raw .#carbide-api-container)
```

Lists every store path the result depends on. A "closure" is the
transitive set of dependencies that must be present for the output
to run — this is what `nix copy` pushes when you publish to a cache.

Tree view:

```sh
nix-store --query --tree $(nix eval --raw .#carbide-api-container)
```

## Interactive dependency explorer

```sh
nix run nixpkgs#nix-tree -- --no-link .#carbide-api-container
```

TUI for browsing dependency graphs. Arrow keys to navigate, shows
sizes and references. Most useful tool for understanding "why is
this closure so large?" or "what transitively pulls in glibc?".

## Compare two derivations

```sh
nix store diff-closures \
  /nix/store/old-hash-carbide \
  /nix/store/new-hash-carbide
```

Shows which paths were added, removed, or changed versions between
two builds. Useful after an upgrade to see what actually moved.

## See build logs

```sh
nix build .#carbide-api-container --print-build-logs
```

Shows stdout/stderr of the build in real time. For already-built
derivations, show the stored log:

```sh
nix log /nix/store/abc123-carbide-api.drv
```

## Debug "why did this rebuild?"

When a `nix build` unexpectedly rebuilds something, compare the
derivation hash before and after the change:

```sh
# Before your change
nix eval --raw .#carbide-api.drvPath > /tmp/before.drv

# (make the change)

# After your change
nix eval --raw .#carbide-api.drvPath > /tmp/after.drv

diff /tmp/before.drv /tmp/after.drv
```

If the hashes differ, ask what inputs changed:

```sh
nix derivation show $(cat /tmp/before.drv) > /tmp/before.json
nix derivation show $(cat /tmp/after.drv) > /tmp/after.json
diff /tmp/before.json /tmp/after.json
```

This will show exactly which env vars or source paths differ between
the two derivations.

## Verify source filter isn't over-invalidating

The expensive derivation is `deps` (external dependency compilation).
It should only rebuild when `Cargo.lock` or workspace `Cargo.toml`
files change — not when any `.rs` file changes.

Test:

```sh
# Baseline
nix eval --raw .#deps.drvPath
# /nix/store/abc123-carbide-workspace-deps-.drv

# Edit some .rs file, save it
nix eval --raw .#deps.drvPath
# /nix/store/abc123-carbide-workspace-deps-.drv  ← should be same hash

# Edit Cargo.lock (e.g., cargo update some-dep), save it
nix eval --raw .#deps.drvPath
# /nix/store/def456-carbide-workspace-deps-.drv  ← different hash expected
```

If the hash changes on a `.rs` edit, the source filter for `depsSrc`
is too broad. Check `craneLib.cleanCargoSource` is being used for
`buildDepsOnly`, not the full `src`.

## Binary cache diagnostics

Check if a derivation is available in a configured binary cache:

```sh
nix path-info --store https://cache.nixos.org .#deps 2>&1
```

Replace the store URL with your cache. A success means the cache
has the output; an error means it'll have to build locally.

See why Nix chose to build vs. fetch:

```sh
nix build .#carbide-api-container --print-build-logs -v 2>&1 | grep -E 'building|copying|substituting'
```

Look for lines like:
- `copying path '...' from 'https://cache.nixos.org'` — cache hit
- `building '...'` — no cache hit, building from source
- `substituting '/nix/store/...'` — fetching from cache

## List what you've built

Everything in `/nix/store` that looks like carbide:

```sh
ls /nix/store/ | grep -E 'carbide|forge-' | head -20
```

## Garbage collection

When the store gets too big, clean up old build outputs that nothing
currently references:

```sh
nix-collect-garbage
```

Or more aggressive — also delete old generations of your flake's
build outputs:

```sh
nix-collect-garbage --delete-older-than 7d
```

Note: this removes build artifacts. You'll rebuild next time.
Usually fine unless you're offline.

## Useful aliases

Add to `.bashrc` or `.zshrc` for convenience:

```sh
alias nix-drv='nix eval --raw'                  # usage: nix-drv .#carbide-api-container.drvPath
alias nix-show='nix derivation show'            # usage: nix-show .#carbide-api-container
alias nix-deps='nix-store --query --requisites' # usage: nix-deps /nix/store/...
alias nix-tree-it='nix run nixpkgs#nix-tree --'  # usage: nix-tree-it .#carbide-api-container
```
