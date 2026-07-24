# Deferred work

## otelcol-contrib: commit OCB-generated go.mod/go.sum

The `otelcol-contrib-container-arm64` Nix build requires committed `go.mod` and
`go.sum` files from a local OCB run. These live at
`bluefield/otel/ocb-generated/go.mod` and `.../go.sum` and are NOT checked in yet.

Run `bluefield/otel/update-ocb-modules.sh` (requires OCB on PATH):

```sh
nix shell nixpkgs#opentelemetry-collector-builder
bash bluefield/otel/update-ocb-modules.sh
```

The script handles version substitution, running OCB, and copying the
outputs. After it finishes:

```sh
git add bluefield/otel/ocb-generated/
# Set vendorHash = pkgs.lib.fakeHash in nix/container/otelcol-contrib-aarch64.nix
nix build .#otelcol-contrib-container-arm64   # fails with correct hash
# Paste the "got:" sha256 into vendorHash and rebuild
```

**When the OCB config changes** (new component, version bump in
`otelcol_builder_config_yaml.txt` or `otelcol_version.txt`):
re-run the script and repeat the steps above.

---

## GitHub Actions: multi-arch container build and push

Multi-arch manifest creation was removed from the Nix flake (was in
`multiArchApps`). CI should handle it instead using crane/skopeo directly.

Proposed two-job pattern:

**Job 1 — `build` (matrix, `fail-fast: true`)**

One variant per `{service, arch}` pair (flat `include:` list, not a
cross-product, since not every service has an arm64 variant). Each job:

1. `nix build .#<service>-container[-arm64] -o result-<arch>`
2. Pushes the single-arch image to the registry with a temporary tag
   `ghcr.io/nvidia/<service>:${SHA}-amd64` / `...-arm64` using
   `skopeo-nix2container` (from the nix2container flake input) for the
   `nix:` transport.

**Job 2 — `push-manifests` (`needs: build`, `if: success()`)**

`needs` on a matrix job blocks until ALL variants complete. If any matrix
job failed, `if: success()` skips this job entirely. Creates manifest lists:

```
crane index append \
  --tag ghcr.io/nvidia/<service>:${SHA} \
  -m ghcr.io/nvidia/<service>:${SHA}-amd64 \
  -m ghcr.io/nvidia/<service>:${SHA}-arm64
```

**Trade-off accepted:** single-arch images are pushed to the registry
during the matrix phase. They are not referenced by any manifest list
until job 2 completes, so they are invisible to k8s/docker pull. Registry
retention policies GC orphaned tags on failure.

**Tooling needed in CI:**
- `DeterminateSystems/nix-installer-action` for Nix + flakes
- `docker/login-action` for registry auth before the skopeo push
- `skopeo-nix2container` via `nix shell github:nlewo/nix2container#skopeo-nix2container`
- `crane` via `nix shell nixpkgs#crane` or standalone binary

---

# Deferred work — carbide-extras integration

## Context

`carbide-extras` (gitlab-master.nvidia.com/.../carbide-extras) is the
proprietary package source of truth. It currently produces a self-serving
APT repository container (`carbide-apt-repo:latest`) that Ubuntu-based
hosts `apt install` from at runtime. Packages today:

- `nvinit` (arch:all) — scripts + systemd units for NVIDIA init
- `benchpress` (arch:all) — benchmark harness
- `forge-ca` (arch:all) — CA certificates for forge
- `tools` (per-arch amd64/arm64) — vendor binary collection
- `libnss-*` (per-arch) — pre-built, checked into `dist/`

Two Ubuntu releases supported: `ubuntu2204` (jammy), `ubuntu2404` (noble).

The NixOS scout-oss image cannot use the existing apt flow at runtime
(no apt, no /var/lib/dpkg, no FHS layout). Integration has to happen
at flake-evaluation time via the optional `carbide-extras` flake input
that `nix/extras-stub/flake.nix` defaults to empty.

## Open items

### Carbide-extras-side (gitlab repo)

- Add `flake.nix` that exports `scoutOssExtraModules.<system>` per the
  contract documented in `nix/extras-stub/flake.nix` of this repo.
- Repackage each release/architecture/package source dir as a Nix
  derivation, bypassing legacy packaging metadata. Pattern: extract
  source files, `mkDerivation` with `installPhase` that lays files
  into `$out` directly. autoPatchelfHook for any binary tools that need
  ELF patching.
- Wire each package as a NixOS module that adds it to
  `environment.systemPackages`, declares `systemd.services` for unit
  files, etc.
- Decide whether `tools` (per-arch) splits into separate modules or
  one arch-aware module. Same question for `libnss-*`.

### CI architecture

GitHub actions cannot reach gitlab. Three patterns documented in
chat history:

- **A. Self-hosted github runner inside nvidia network** — runner has
  gitlab read access; one workflow file for both variants.
- **B. One-way mirror gitlab→github (private)** — gitlab pushes to a
  private github mirror on every merge; github actions reads via PAT.
  Proprietary content has a copy on github (auth-gated).
- **C. Move proprietary container build to gitlab CI** — gitlab fetches
  carbide flake from github (allowed direction), runs `nix build`
  with `--override-input`, pushes container to nvcr.io.

Decision deferred. **Pattern C looks cleanest** (clean separation: github
builds public, gitlab builds proprietary, both push to nvcr.io) but
requires moving the proprietary `build-release-artifacts` job out of
github actions into gitlab CI.

### Apt-repo coexistence

The existing `carbide-apt-repo:latest` container path needs to keep
working during the migration — non-NixOS hosts (mkosi-built scout-oss
on Ubuntu) still apt-install from it.

- Keep cargo-make's `build-apt-repo-container` path alive in parallel.
- Once all hosts migrate to NixOS scout-oss, the apt flow can be
  retired. Until then, both deployment models coexist.

### Aarch64 considerations

`scout-oss-image-aarch64` (not yet implemented) will also need extras.
`scoutOssExtraModules.aarch64-linux` should mirror x86 — same packages,
arm64 binaries where applicable. Blocking work: aarch64-aware versions
of `nvidia-imex.nix` and `mft.nix` (URL switching), plus the
`sha256_aarch64` hash in flake.nix's `dc_580` mkDriver call.

## Architectural notes

- The carbide flake's `carbide-extras` input is a *single slot*. If
  multiple proprietary sources eventually need composition, the
  carbide-extras flake itself becomes the composition point — it can
  pull in N sub-flakes and merge them, exposing one
  `scoutOssExtraModules` to consumers. Keeps the public flake's input
  surface stable.
- Override syntax for internal builds:
  ```sh
  nix build .#scout-oss-image-x86 \
    --override-input carbide-extras git+ssh://git@gitlab-master.nvidia.com/.../carbide-extras
  ```
- Local dev override (e.g. while developing carbide-extras):
  ```sh
  nix build .#scout-oss-image-x86 \
    --override-input carbide-extras path:/home/$USER/src/.../carbide-extras
  ```

## Inspection / tooling oddities encountered

- `objcopy` on x86 host can't read aarch64 PE32+ binaries (`file
  format not recognized`). To inspect aarch64 UKI sections, use
  `aarch64-linux-gnu-objcopy` (in `pkgs.pkgsCross.aarch64-multiplatform.binutils`)
  or run inspection on an aarch64 host. `file scout.efi` works
  cross-arch and confirms the file type / target arch.
- `restApiVendorHash` in `flake.nix` is still `pkgs.lib.fakeHash`, so
  the exposed rest-api Go binary/container package attrs evaluate but
  won't build until the real vendor hash is captured.
- `pxe/common_files/scout-loader-rclocal` is the tracked source-of-
  truth for the loader's rc.local; the per-arch destinations under
  `pxe/mkosi.profiles/scout-loader-{x86_64,aarch64}/mkosi.extra/etc/rc.local`
  are gitignored (cargo-make copies them at build time). NixOS scout-loader
  config reads the source file directly.
- **`pxe/Makefile.toml` assumes Debian/Ubuntu host for several BFB
  tasks.** `bfb-copy-efi` runs `apt-get install file`; similar
  `apt-get` calls likely exist in other tasks (worth grepping
  `pxe/Makefile.toml` for `apt-get` and `dpkg-`). On non-Debian hosts
  these fail with exit 100. Fixed `bfb-copy-efi` to guard the install
  with `command -v file ||` — same pattern can be applied elsewhere
  if/when other tasks need to run on Arch/NixOS/Fedora dev boxes.
- **`cp` from /nix/store into the source tree creates 0444 files.**
  Files in `/nix/store` are read-only (mode 0444/0555). A plain `cp`
  preserves that mode, so the destination becomes read-only too —
  fine on first run, but the *second* run fails with `cp: cannot
  create regular file '...': Permission denied` when trying to
  overwrite. Use `install -m 0644 <src> <dst>` instead of `cp` for
  any task that copies Nix-build outputs into the source tree.
  Affects `ipxe-aarch64-from-nix` and `setup-apt-repo-arm64-from-nix`;
  both fixed. Tasks that copy into `${BUILD_LOCATION}` (a tmpdir
  cleaned each run) aren't affected.
- **iPXE has its own `result-ipxe-aarch64/` symlink, separate from
  `bfb-stage`.** `nix/boot/ipxe-aarch64.nix` hardcodes
  `pkgsCross.aarch64-multiplatform.gcc13Stdenv` — cross-compile-only
  regardless of which system iteration evaluates it. We keep it
  invoked as `.#packages.x86_64-linux.ipxe-efi-aarch64` because the
  cross-compile from local x86 host (~90 s) is faster than the
  remote-aarch64-builder roundtrip (SSH + closure copy easily
  outweighs the build itself). The cost is two separate `nix build`
  commands and two result symlinks. To consolidate, rewrite
  `ipxe-aarch64.nix` to be system-aware (~6 lines of conditional
  picking `pkgs.stdenv` on aarch64 hosts, `pkgsCross` on x86).
- **OOM on the Graviton builder is `max-jobs`, not `cores`.**
  `cores` limits threads *within* a rustc invocation; `max-jobs`
  (4th field of local `builders =`) limits how many derivations
  the daemon dispatches in parallel. 8 GB c7g.xlarge needs
  `max-jobs ≤ 2` for carbide. See "Memory ceiling" in
  `docs/nix-aarch64-builder-setup.md`.
- **iPXE EMBED script must be passed to the Nix builder.** Both
  `nix/boot/ipxe-{aarch64,x86}.nix` previously omitted `EMBED=` from
  the iPXE `make` invocation, so the resulting EFI images had no
  embedded boot script — iPXE ran only its built-in autoboot per-NIC
  and fell through to "Nothing to boot" when DHCP didn't offer a
  next-server/filename. Symptom: banner shows "Carbide", BF-3 NICs
  detected as expected, but no `Carbide - <version>` line from
  `pxe/ipxe/local/embed.ipxe`. Fixed by adding `embedScript` param
  to both derivations and `EMBED=${embedScript}` to the make line —
  mirrors cargo-make's `ipxe-build-efi-*` tasks.
- **The Nix admin CLI package uses a stale Cargo package name.**
  `crates/admin-cli/Cargo.toml` defines `nico-admin-cli`, but the native
  and aarch64 package sets call the Rust builders with
  `pname = "carbide-admin-cli"`. Those derivations pass the stale name
  to `cargo --package` and should be updated while retaining any desired
  public Nix attribute aliases.
