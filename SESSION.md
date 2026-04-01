# Deferred work

## BFB assembly: Nix produces inputs, cargo-make assembles

Decided 2026-05-11: do not build the BFB in Nix. The signed-bundle
mlx-mkbfb extract/repack and the NGC-authenticated HBN inputs
(container, configs, zip) stay in cargo-make. Nix produces only the
carbide-built *inputs*; cargo-make does the assembly via a parallel
`-from-nix` task tree.

Operator workflow (reproducible from a fresh clone):

```sh
nix build .#packages.aarch64-linux.bfb-stage
nix build .#packages.x86_64-linux.ipxe-efi-aarch64 -o result-ipxe-aarch64
cargo make --cwd pxe build-boot-artifacts-bfb-from-nix
```

What Nix produces:

- `forge-dpu-package` — composite DPU package artifact (3 Rust binaries
  + scripts/units/configs). See the current Nix packaging expression.
- `bfb-stage` — flat `$out` tree: `forge-scout` binary,
  DPU package artifact, and scout package artifact. See the current Nix
  staging expression.
- `ipxe-efi-aarch64` — staged separately under
  `result-ipxe-aarch64/`; cross-compiled from x86 host because the
  cross-compile is faster than the SSH+store-copy roundtrip to the
  aarch64 remote builder.

What cargo-make does (in `build-boot-artifacts-bfb-from-nix`):
upstream signed BFB download, mlx-mkbfb extract/inject/repack, HBN
container pull + extract, apt-pool population, final sign/pack. The
`-from-nix` task variants (`bfb-add-scout-to-bfb-from-nix`,
`cp-forge-dpu-package-to-bfb-from-nix`,
`setup-apt-repo-arm64-from-nix`, `ipxe-aarch64-from-nix`) read from
`${REPO_ROOT}/result/` and `${REPO_ROOT}/result-ipxe-aarch64/`
instead of `target/...`, and drop the cargo-build dependencies that
would otherwise rebuild from source.

Open follow-ups:

- **forge-dpu package Phase 3c** — add `otelcol-contrib` (Go via OCB),
  `node_exporter` (prebuilt), `transceiver-exporter` (Go) plus their
  systemd units and config fragments to the composite package artifact.
  Documented inline in the current DPU packaging expression.
- **SA_ENABLEMENT path** — only the non-SA `internal-bfb-aarch64`
  was wired to `-from-nix`. Production sign-and-attest flows would
  need a matching `internal-bfb-aarch64-sa-from-nix`.

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

## Distributed builds — multi-builder pool (deferred)

Single aarch64 builder works today (EC2 Graviton). Future: scale to
multiple builders for parallelism, particularly under CI load.

Setup pattern: `/etc/nix/nix.conf` accepts either inline semicolon-
separated `builders =` entries or `builders = @/etc/nix/machines`
referencing a machines file. Machines-file format per line:

```
ssh-ng://user@host  systems-csv  ssh-key  max-jobs  speed-factor  features-csv
```

Example x86 + aarch64 mixed pool:

```
ssh-ng://nix@x86-builder1.internal  x86_64-linux  /etc/nix/build_key 8 1 nixos-test,big-parallel,kvm
ssh-ng://nix@x86-builder2.internal  x86_64-linux  /etc/nix/build_key 8 1 nixos-test,big-parallel,kvm
ssh-ng://ubuntu@98.91.24.31         aarch64-linux /etc/nix/aws_key   8 1 nixos-test,big-parallel,kvm
```

Important properties to remember:

- A single derivation runs on **one** builder — no fan-out within a
  derivation. The kernel compile won't split across three machines.
- Parallelism is **across** independent derivations in the dep graph.
  `nix build .#a .#b .#c` with three builders → up to 3× wall-clock
  speedup on independent leaves.
- Each builder has its own `/nix/store`. `builders-use-substitutes =
  true` lets each builder independently fetch from cache.nixos.org
  rather than uploading from the local store via SSH.
- `speed-factor` weights the scheduler — set faster machines higher.
- For CI runners, each runner has a fresh `/nix/store`. Self-hosted
  binary cache (attic / S3 / cachix) recovers shared-cache benefits
  across runners.

When this becomes worth setting up:
- Multiple developers iterating simultaneously (shared build farm).
- CI parallelism dominating wall-clock — particularly when each scout-
  oss / scout-loader / qcow-imager builds independently across arches
  on each PR.
- Per-arch CI runner pools where one Graviton instance saturates.

Until then, single-builder-per-arch is fine.

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
