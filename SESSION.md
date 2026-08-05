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
- `carbide-dhcp` cannot be cross-compiled for aarch64: it links against
  Kea, and nixpkgs' Kea builds with meson, which aborts with "Can not
  run test applications in this cross environment". This is why
  `carbide-dhcp-container-arm64` and `forge-dhcp-server-container-arm64`
  fail, and why `carbide-dhcp` is named in the `skip` list of the
  `aarch64-page-size` check in `flake.nix`. Fixing Kea means deleting
  that entry.
- A stale `restApiVendorHash` breaks every rest-api Go binary, and the
  breakage is invisible to anything short of a build: the attrs still
  *evaluate*, so `nix flake show` and any eval-only check pass green
  while all 22 binaries and their containers fail to realise. Worth
  remembering whenever "the flake evaluates" is offered as evidence.
- `env.GOARCH` does nothing in `buildGoModule`. nixpkgs'
  `pkgs/build-support/go/module.nix` ends with

      env = args.env or { } // { inherit (go) GOOS GOARCH; };

  so the caller's value is overwritten unconditionally, and the target
  architecture can only be selected by choosing the package set. This is
  a silent failure: the build succeeds, the attribute is still called
  `-aarch64`, and the binary inside is amd64. Architecture must come from
  `pkgsCross`, the same way the Rust and third-party derivations do it.
- `-extldflags '-static'` is inert when `CGO_ENABLED=0`, because the
  external linker never runs. It reads as enforcing static linkage while
  enforcing nothing, and on a cross build it does harm: it drags in the
  external linker, which fails with `cannot find -lc` since there is no
  static aarch64 libc. `-linkmode internal` is the flag that actually
  expresses the requirement on both arches. Note the fallback is quiet —
  drop the flag entirely and cross builds come out dynamically linked
  against a `/nix/store` glibc, which still works inside an image built
  from the closure.
- The `aarch64-page-size` check covers only the Rust aarch64 binaries,
  matching the cargo-make task it replaces. The Go binaries were measured
  by hand and are fine (`page_size=0x10000`), but they are not wired into
  the check.
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

## Resolved: scout is kexec'd, not soft-rebooted into

The two-stage design is intact, but the hand-off is now kexec. Established by
QEMU boot tests, in the order the failures surfaced — all three are worth
knowing, because each is silent:

1. `systemctl soft-reboot` **ignores** `/run/nextroot` unless it validates as
   an OS tree, logging only at debug level:

       Failed to determine if /run/nextroot/ is a valid OS tree, ignoring

   and then soft-reboots the *current* system. The machine comes back healthy
   in the loader, so it reads as a failed fetch rather than a failed pivot.
   Validation wants an `os-release`, and it must be a real file: the check runs
   pre-pivot, where an absolute `/nix/store` symlink still resolves against the
   loader's root.
2. Past that, PID 1 freezes with `Failed to open serialization fd`. nixpkgs
   patches systemd to re-exec from `/run/current-system/systemd/lib/systemd/systemd`,
   and soft-reboot preserves `/run` — so post-pivot that names the *loader's*
   toplevel, absent from the store just mounted.
3. Past that, systemd starts and dies on `Unit default.target not found`. This
   is the design, not a bug: `system.build.squashfsStore` holds only
   `/nix/store`. The units are all *there* — `forge-scout`, `getty.target`,
   `nv-hostengine` are in the store's `etc` closure — but `/etc` is
   *materialised* by `$toplevel/activate`, which runs from stage 1. Nothing is
   missing from the image; something has to run against it.

`system.etc.overlay.enable` is not a way out either: the remount is done by a
systemd mount unit or the activation script, both of which need `/etc` to be
reachable already.

The deciding argument was not boot time but kernels. A soft-reboot never
restarts the kernel, so scout would have run on the *loader's* kernel and never
its own. Both configurations happen to resolve to the same store path today,
but that is a coincidence of taking the default kernel with the same config —
and it breaks where this port is heading, since the aarch64 profile wants a
64K-page Grace kernel (`linux-nvidia-64k-hwe-24.04` in mkosi) that the loader
has no reason to carry. Scout's NVIDIA modules are built against one specific
version. Under kexec the kernel and its modules always ship together.

Verified end to end in QEMU: loader boots, fetches, measures, `kexec`s, and
scout comes up with sshd, lldpd, networkd, DCGM `nv-hostengine`, IMEX and the
update timer, reaching `scout login:`. `nvidia-fabricmanager` is the only
failing unit, having no NVSwitch to talk to in a VM.

Costs and unknowns carried forward:

- kexec skips firmware entirely — no POST, no memory training — but does
  re-initialise every driver. In QEMU scout reached a login prompt at 12.7s;
  the real cost on a GPU node with many NVMe and ConnectX devices has not been
  measured.
- The 1.4 GB initrd must be resident while the old kernel is still running.
- kexec is not always reliable on server firmware with IOMMU enabled and GPUs
  bound. Only real hardware will settle that.

## aarch64 cross-building works, but never hits the public cache

`nix build .#qcow-imager-aarch64` completes from an x86 host and produces a
valid ARM64 UKI (479 MB, `PE32+ … ARM64`), kernel and all. No cross-compile
failure anywhere in the closure. That was the biggest unmeasured risk in the
aarch64 plan and it is now settled for the UKI roles; scout still needs the
`dc_590` override before it can be tried.

It also confirms the `uki.nix` change from Phase 0 was load-bearing: the
output is an ARM64 PE, so `efiArch` resolved to `linuxaa64.efi.stub`. With the
old signature — `pkgs` as a parameter alongside a cross-built system — this
would have produced an x86-64 stub wrapping an aarch64 kernel, which firmware
rejects without explanation.

**The cost is that cross-compiling defeats `cache.nixos.org` completely.**
Hydra builds aarch64 natively, so the cross derivation of the same software is
a different store path that nobody upstream has ever built:

    cross-built   v3gblfy4…-linux-aarch64-unknown-linux-gnu-6.18.39   404
    native        68bgfsqv…-linux-6.18.39                             200

Same kernel version, same nixpkgs. This is not a first-build cost: nothing in
the aarch64 closure — kernel, glibc, gcc, systemd — will ever substitute from
the public cache, on any machine, ever. Every fresh store pays for the whole
aarch64 world from source.

So `just image-aarch64 <name>` builds `packages.aarch64-linux.*` and is the
canonical path. No host detection is needed anywhere: these are ordinary
`aarch64-linux` derivations, and Nix already realises them whichever way the
host allows — natively on an arm64 runner, under binfmt on x86, or offloaded
to a remote builder. One recipe covers CI and every developer machine.

Two things are needed for the binfmt route, and registered handlers are only
the first. Nix must also be *allowed* to build for the platform:

    extra-platforms = aarch64-linux i686-linux x86_64-v1-linux ...

Without it, an `aarch64-linux` derivation fails with "platform mismatch —
Required system: 'aarch64-linux', Current system: 'x86_64-linux'" even with
`qemu-user-static` installed and binfmt registered. Confirmed by A/B on the
same derivation: fails without `--extra-platforms aarch64-linux`, builds and
runs with it. `nix config show extra-platforms` reports the client's view
rather than what the daemon accepts, so verify by building, not by reading.

`image-aarch64-cross` remains as an escape hatch, not an alternative. It earns
its keep only when there is no aarch64 execution available at all, or for a
compile-bound image where native-speed x86 compilation beats emulated
compilation. Reaching for it to work around a failing native build is what
fragments the cache.

The native attrs are ordinary `aarch64-linux` derivations, so they run on a
remote builder or under binfmt, and the base arrives prebuilt — the kernel is
downloaded rather than emulated, which is why emulation is much cheaper here
than the 5–20× figure suggests. The cross attrs need nothing but produce store
paths no cache will ever hold.

Native is canonical: CI runs on `linux-arm64-*` runners where it is simply the
native build, and developers with a builder or binfmt share those exact paths,
so one cache serves everyone. Cross stays as the fallback for working offline
or with no aarch64 execution available.

The consequence to keep in mind is that the two are *different store paths*. A
cache populated by CI's native builds will never serve someone's cross builds.
That is inherent, not a bug, and it is the reason to steer people at the native
path rather than letting the choice drift.

`docs/nix-aarch64-builder-setup.md` is therefore not obsolete — it is the
runbook for one of the two routes, and now also documents the binfmt
alternative and how to decommission a builder cleanly. A `builders =` line
naming a deleted host does not fail gracefully; aarch64 builds try to offload
to a dead address.

## aarch64 GPU stack: IMEX is fine, fabricmanager is broken two ways

Checked before writing the `dc_590` aarch64 override, because both of these
fail on real GPU hardware rather than at build time.

**IMEX — no problem.** `cudaPackages_13_1.imex` resolves for aarch64 to
`.../redist/imex/linux-sbsa/imex-linux-sbsa-590.48.01-archive.tar.xz`, which
exists upstream, at the version that matches `dc_590`. The version assertion
in `scout-nvidia.nix` needs no arch guard and aarch64 scout keeps IMEX.

**fabricmanager — two separate bugs in nixpkgs, and the loud one hides the
quiet one.**

`pkgs/os-specific/linux/nvidia-x11/fabricmanager.nix` derives both its
download path and its ELF interpreter by reversing `stdenv.system`:

    sys  = linux-aarch64          (from aarch64-linux)
    bsys = linux-aarch64

1. **The source 404s.** NVIDIA publishes the aarch64 server build under
   `linux-sbsa`, not `linux-aarch64` — the same naming split as the DCGM
   repo. Measured:

       404  .../fabricmanager/linux-aarch64/fabricmanager-linux-aarch64-590.48.01-archive.tar.xz
       206  .../fabricmanager/linux-sbsa/fabricmanager-linux-sbsa-590.48.01-archive.tar.xz

2. **The interpreter does not exist.** The install phase runs
   `patchelf --set-interpreter ${stdenv.cc.libc}/lib/ld-${bsys}.so.2`, giving
   `ld-linux-aarch64.so.2`. aarch64 glibc ships only `ld-linux-aarch64.so.1`
   (verified against the aarch64 `stdenv.cc.libc`). patchelf accepts a
   non-existent interpreter without complaint, so the build would succeed and
   the binary would fail at exec with a misleading `No such file or directory`.
   On x86_64 the same expression yields `ld-linux-x86-64.so.2`, which is
   correct — hence nobody has noticed.

Bug 1 masks bug 2: the fetch fails before anything can be patched. Fixing only
the URL produces a fabricmanager that builds and cannot run — confirmed, not
predicted: with the sbsa URL in place the build got as far as
`versionCheckHook` and died with

    qemu-aarch64-static: Could not open '.../ld-linux-aarch64.so.2': No such file or directory

**A third trap sits on top of the fix.** `fabricmanager.nix` sets
`dontFixup = true` (its comment cites stdenv shrinking leaving undefined
symbols in these prebuilt binaries), so a `postFixup` hook never runs at all —
the phase log goes straight from `installPhase` to `installCheckPhase`. The
correction has to hang off `postInstall`, which that file's `installPhase` does
invoke, and which lands after the wrong interpreter is written and before
anything tries to execute the binary.

Both fixes live in `nix/os/nvidia-driver.nix`, applied only on aarch64 — the
whole override is guarded rather than its contents, because setting
`postInstall = ""` where the attribute was absent is itself enough to change a
derivation hash. Verified: x86 `scout-kexec` keeps its exact store path, and
the aarch64 fabricmanager builds with both binaries carrying
`ld-linux-aarch64.so.1`. That build passing `versionCheckHook` is the proof it
runs — the hook executes `nv-fabricmanager --version` under emulation.

Both binaries matter to scout: `nv-fabricmanager` backs the
`nvidia-fabricmanager` service, and `nvswitch-audit` is named directly in
`scout-nvidia.nix`'s systemPackages. `nvidia-imex` and `nv-hostengine` are
both ordered after fabricmanager, so a broken one stalls the GPU units rather
than failing in isolation.

## Signing the scout update cache: what it actually takes

The `--no-check-sigs` in `nix/os/scout.nix` cannot be removed by adding a
public key, which is what the comment there used to imply.

The cache scout substitutes from is **not** the S3 build cache. It is the
flat-file cache inside the boot-artifacts payload, served over HTTP from
carbide-static-pxe, and it is built by `pkgs.mkBinaryCache`. That function has
no signing support whatsoever — its `make-binary-cache.py` writes

    StorePath URL Compression FileHash FileSize NarHash NarSize References

and never a `Sig:` line. Pre-signing the store paths does not help either:
`exportReferencesGraph`, which is how the derivation learns the closure,
carries no signatures.

Signing therefore has to happen outside a derivation, because
`nix store sign` needs the private key and a derivation would put it in the
store:

    SCOUT=$(nix build --no-link --print-out-paths .#scout-kexec)
    TOP=$(sed 's/ .*//; s|^init=||; s|/init$||' "$SCOUT/scout.cmdline")

    nix store sign --key-file ./cache-priv.pem --recursive "$TOP"
    rm -rf ./result-scout-cache
    nix copy --to "file://$PWD/result-scout-cache?compression=zstd" "$TOP"

then stage `result-scout-cache/` into the webroot like the other artifacts,
drop `scoutCache`/`mkBinaryCache` from `nix/container/boot-artifacts.nix`, and
in `scout.nix` set

    nix.settings.trusted-public-keys = [ "nico-cache-1:..." ];

and remove `--no-check-sigs`.

This is the Phase 5 seam again — Nix produces artifacts, cargo-make assembles
the payload — so it is not a new pattern, but it does give up the property
`boot-artifacts.nix` was written for: that the payload cannot contain a stale
artifact. A cache staged separately from the kernel and initrd beside it can
drift, and the failure mode is bad: scout finds a newer toplevel published,
fetches it, and the closure is not in the cache, so it reboot-loops. The
staging task should assert the pair matches:

    hash=$(basename "$TOP" | cut -d- -f1)
    test -f "result-scout-cache/$hash.narinfo" \
      || { echo "cache does not contain $TOP"; exit 1; }

One line, and it turns a field reboot-loop into a build failure.

Not urgent: it only pays off once scout does self-updates in anger. Until
then `--no-check-sigs` against a cache served from carbide's own webroot is
defensible.

## aarch64 scout needs a 64K-page kernel, and it is not free

Grace requires 64K pages. nixpkgs sets no arm64 page size at all — it takes the
kernel defconfig, which is 4K — so `nix/os/scout.nix` overrides
`ARM64_4K_PAGES`/`ARM64_64K_PAGES` for aarch64 only. The mkosi profile got the
same thing by installing Ubuntu's `linux-nvidia-64k-hwe-24.04`.

The cost is structural rather than incidental: a custom kernel config is a
derivation nobody upstream builds, so it never substitutes.

    200  68bgfsqv…-linux-6.18.39   default 4K kernel
    404  8zrzkjav…-linux-6.18.39   64K kernel

Under binfmt emulation that means compiling a kernel under qemu on every empty
store. This is the strongest argument in the tree for a real aarch64 builder:
with one, the kernel compiles once at native speed and then lands in our own
cache for everyone else.

Scoped to scout deliberately. The loader and qcow-imager keep the cached 4K
kernel:

    scout-kexec   8zrzkjav…  64K, built
    scout-loader  68bgfsqv…  4K, substituted
    qcow-imager   68bgfsqv…  4K, substituted

**This retroactively settles the kexec-vs-soft-reboot decision.** A soft-reboot
never restarts the kernel, so scout would have run on the loader's 4K kernel
and 64K pages would have been unreachable without also rebuilding the loader on
a custom kernel it has no use for. The argument made at the time was that
soft-reboot silently pins scout to the loader's kernel; this is that argument
becoming concrete.

It also promotes the `aarch64-page-size` check in `flake.nix` from precaution
to live defence — against a 64K kernel, 4K-aligned PT_LOAD segments genuinely
fail to map.

## Boot images are a matrix in nix/os/images.nix

`nix/os/images.nix` is now the only file that enumerates architectures. Three
roles — `scout-kexec`, `scout-loader`, `qcow-imager` — in two shapes: scout
publishes kernel/initrd/cmdline, the other two are UKIs. flake.nix calls it
once and merges the result into `packages`, so a new image or a newly
buildable architecture needs no edit there.

`targets` lists the roles each architecture can produce, rather than taking a
full cross-product, because the product is not square: aarch64 scout does not
evaluate today. `dc_590` omits `sha256_aarch64`, so nixpkgs declares it
x86_64-only and evaluation fails with "unsupported system". Listing what each
target can actually build keeps that a stated fact instead of a broken
attribute that surfaces in CI. Adding scout to aarch64 is one word once the
driver override lands.

Verified as a pure refactor: `scout-loader`, `scout-kexec`, `qcow-imager` and
`boot-artifacts-x86-64-container` all keep byte-identical store paths, and the
aarch64 derivations match those produced by a hand-written evaluation before
the file existed. `nixpkgs.buildPlatform` is only set when it differs from the
build system, which is what keeps the native paths unchanged.

## qcow-imager: ported for x86, mkosi profiles retained until aarch64 lands

`nix/os/qcow-imager.nix` + `nix/os/uki.nix` replace the qcow-imager mkosi
profiles. Booted under OVMF as a UKI, which is the first time `uki.nix` has
been proven — the scout loader UKI shares that code path and had only ever
been boot-tested as kernel+initrd.

`disk_imaging.sh` runs unmodified and behaves correctly:

    Working serial ports = [ttyS0 ttyAMA0]
    Using serial port: [ttyS0] (0)
    Could not resolve disk image to use from arguments in /proc/cmdline
    Rebooting

All sixteen commands it shells out to resolve in the unit's PATH, checked
against the script rather than copied from the mkosi package list. `update-grub`
is deliberately *not* among them: the script runs it as
`chroot /mnt /bin/sh -c update-grub`, so it has to resolve inside the imaged
filesystem — the customer's grub, for the customer's disk.

`pxe/mkosi.profiles/qcow-imager{,-aarch64}` are deliberately still present.
Deleting them now would leave the aarch64 imager unbuildable by either path
until Phase 4 ports it; they go together with the aarch64 port, along with
`stage-disk_imaging-script` and the `mkosi-*-qcow-imager*` tasks.

The aarch64 profile's `mkosi.postinst.chroot` needs no counterpart — it gunzips
Ubuntu's compressed arm64 vmlinuz so the UKI stub can use it, and NixOS builds
an uncompressed `Image` on aarch64 that `uki.nix` picks up directly.

## mkosi → NixOS scout: state of the port

Two flake targets mirror the two mkosi profiles. Both build; the loader
boots, fetches and measures correctly. The pivot does not work — see the
blocker above.

    nix build .#scout-loader   scout-loader.efi        375 MB   (mkosi: 74 MB)
    nix build .#scout-store    scout-store.squashfs   1396 MB   (mkosi: 1488 MB)
                               scout-store.nixos-system

    just scout                              build both
    cargo make --cwd pxe scout-x86_64-from-nix   stage into the webroot

Staging is wired into `build-boot-artifacts-x86-host-from-nix`, beside
`ipxe-x86_64-from-nix`, so it follows the same path CI already uses. The
loader is not staged yet — that needs a second `install` line putting
scout-loader.efi at blobs/internal/x86_64/scout.efi, the path templates.yaml
already points iPXE at.

### The two-stage shape matters

iPXE fetches only the loader. The loader then fetches the ~1.4 GB rootfs from
Linux userspace, where it can retry, report progress, honour `newrootfs=` and
measure the image into TPM PCR 16 before pivoting. An earlier attempt here
served kernel + initrd + store as three files for iPXE to fetch up front; that
booted but silently dropped the measurement and the retry behaviour, and it
has been deleted. Read pxe/common_files/scout-loader-rclocal before changing
the loader — its job is larger than "fetch and switch".

### NixOS roots are not laid out like the Ubuntu one

The squashfs holds only the contents of /nix/store. /etc, /bin and the rest
are produced at boot by the system's activation script, so:

  * the new root is a tmpfs with the store mounted underneath, not the
    squashfs mounted as the root;
  * which system to start cannot be read off the image — a store may hold
    several — so it is published beside the squashfs as a bare store path in
    scout-store.nixos-system, and symlinked to /sbin/init for soft-reboot.

The two files are only meaningful as a pair. Stage them together.

### The loader and the update check derive the same URL

nix/os/scout-loader.nix and the check-scout-updates unit in nix/os/scout.nix
both read `newrootfs=` from /proc/cmdline with the same fallback. They are in
separate files; if either changes the other has to follow, or a machine booted
with an override compares against an image it never booted and reboots in a
loop.

### Loader size

375 MB against mkosi's 74 MB. Getting there meant importing netboot.nix
directly rather than netboot-minimal.nix — the "minimal" profile is minimal
relative to a graphical installer and still carries profiles/base.nix and
profiles/installation-device.nix, which bring a copy of nixpkgs (196 MB),
python3 (127 MB) and vim (43 MB) for the benefit of `nixos-install`.

What remains is mostly irreducible without kernel work:

    143.5 MB  linux-6.18.39-modules   the whole module tree
     60.2 MB  systemd
     55.1 MB  perl                    activation; kept deliberately
     33.5 MB  glibc

The module tree is the only large lever left. mkosi installs
linux-image-*-generic without linux-modules-extra; NixOS ships everything.
Trimming it needs a filtered modulesTree or a custom kernel config.

Also carried deliberately: netboot.nix's register-nix-paths unit, which runs
`nix-store --load-db` and so keeps nix -> boost -> icu4c in the closure for
about 40 MB. Note `nix.enable = false` does not gate it — that option governs
whether NixOS *configures* Nix, not whether the package is in the closure.

### Driver: dc_590, not the 580 the mkosi profile pins

IMEX refuses to run against a driver it does not recognise, so driver,
fabricmanager and IMEX have to agree. On 580 they do not, in either direction:

    dc_580  580.159.03   imex 580.126.20   mismatched (mkosi pins imex .16)
    dc_590  590.48.01    imex 590.48.01    driver, fabricmanager and IMEX agree
    beta    595.45.04    imex 595.45.04    aligned, but the beta channel and
                                           not a dc_* datacenter package

590 is the newest branch where all three line up on a datacenter driver, and
cudaPackages_13_1 is still CUDA 13, so the DCGM cuda13 plugins stay correct.
An assertion in nix/os/scout-nvidia.nix checks driver == imex; it deliberately
does not check the branch number, because a branch check passes on the broken
580 pairing.

This is a change from what carbide has qualified. Someone who owns GPU
qualification needs to accept 590, or the driver and IMEX need packaging at
the qualified versions.

### nvidia-imex: resolved, from cudaPackages_13_1

`cudaPackages.imex` is in nixpkgs — an earlier note here claimed it needed
packaging, which was wrong. The scope matters, because they carry different
driver branches and the bare default tracks CUDA 12:

    cudaPackages         575.57.08
    cudaPackages_13_0    580.126.20
    cudaPackages_13_1    590.48.01   <- matches dc_590
    cudaPackages_13_2    595.45.04
    cudaPackages_13_3    610.43.02

nix/os/scout-nvidia.nix pins cudaPackages_13_1 and adds an nvidia-imex unit;
the package ships only the binary and a config file, so the config path is
passed on the command line. Ordered after fabricmanager, and Restart=no
because plenty of the machines scout inventories are single-node, where IMEX
exiting is the correct outcome rather than something to loop on.

`nvswitch-audit` and `nv-fabricmanager` come from the driver's fabricmanager
output, which has to be named in systemPackages explicitly — see the port
notes above.

### DCGM: resolved, via NVIDIA's Debian packages

`nix/third-party/dcgm-deb.nix` builds clean and carries
`plugins/cuda13/BwChecker_13` — the exact path the mkosi postinst asserts on.
Wired into `nix/os/scout-nvidia.nix`.

The source route was investigated first and abandoned:

- nixpkgs pins DCGM 4.3.1, whose `cmake/FindCuda.cmake` hardcodes
  `load_cuda(12)`. No overlay can reach CUDA 13 from there; substituting
  `cudaPackages_13` just leaves `CUDA12_*` undefined and CMake fails.
- 4.4.1 rewrote that file to key off `_Cuda_MAJOR_VERSION`, and 4.6.0 declares
  `CUDA_VERSIONS_SUPPORTED = { 13, 12 }`. Either would work in principle, and
  the nixpkgs derivation is already written for it — `cudaPackageSets` is a
  list and the CUDA flags are generated per major version.
- What blocks it is patch rot. Of the four patches nixpkgs carries,
  `remove-cuda-11` and `fix-gcc15` are obsolete on 4.4.1+ (upstream did both
  themselves), `dynamic-libs` needs rewriting as `substituteInPlace`, and
  `fix-paths` needs a genuine rebase — 3 hunks across 3 files, two of them
  tests. 4.4.1 and 4.6.0 fail identically, so 4.6.0 is the better target if
  anyone picks this up.

The deb route avoids all of that and delivers the versions carbide has
actually qualified. Worth revisiting if nixpkgs bumps DCGM.

Notes for whoever maintains it:

- `-cuda13` and `-core` must be the same version; the plugin package declares
  an exact-version `Depends` on core. `-core` is published ahead (4.6.1 while
  `-cuda13` stops at 4.4.2), so do not bump them independently.
- Hashes come from the repo index, not a TOFU build failure. Convert rather
  than transcribe: `nix hash convert --hash-algo sha256 --to sri <hex>`.
- The CUDA runtime is statically linked into the plugins. `BwChecker_13`
  needs `libcuda.so.1` from the driver but not `libcudart` — the separate
  `cuda_cudart` package this file previously called for is not required.

### Ported from the mkosi profiles

Found by diffing against the real scout.squashfs rather than reading
mkosi.conf, which is how several of these turned up:

  * forge-scout-pre — the full script, not just the cmdline parsing: fetches
    the carbide root CA (fatal if it fails; the pem baked into the mkosi image
    is a self-signed CN=site-root that expired in February 2024), generates the
    per-boot SSH keypair, reloads mlx5_ib with udevadm settle either side, and
    re-triggers PCI `add` so drivers rebind.
  * the ipmitool wrapper, which reroutes `lan print` to freeipmi's bmc-config.
    mkosi shadows the real binary via /usr/local/sbin on PATH; there is no such
    directory here, so lib.hiPrio decides the collision instead.
  * check-nvme-drives and fixnvmero as commands on PATH, not units — the first
    is a predicate whose exit status is the interface, the second deletes and
    recreates namespaces and must stay manual.
  * dcgmi-pre (a bare nvidia-smi, which forces the driver's lazy init).
  * disable-mods.conf via boot.extraModprobeConfig. `install <mod> /bin/false`
    is stronger than blacklisting and looks like a hardening requirement.
  * systemd-networkd matching enx*/enp*/enP* with ClientIdentifier=mac,
    lldpd -M 1, hostname, the netdev/lxd groups, RUST_BACKTRACE=full,
    /etc/scout-image-version, timesyncd and resolved.
  * MFT *and* mstflint. They do not overlap — MFT supplies flint, mst and the
    mlx* suite, mstflint supplies the mst* commands — and the image has both,
    from mkosi.conf and from NV_PACKAGES respectively.
  * nvswitch-audit, which was in the closure but not on PATH: the datacenter
    module puts only nvidia_x11.bin in systemPackages and runs fabricmanager
    by store path.

### Build-time validation not reproduced

The mkosi postinst failed the build on any of: a missing `nvidia.ko.zst` or
`mlx5_ib.ko.zst`, `ldd` reporting `not found` for `forge-scout`, `dcgmi`,
`nvvs` or `BwChecker_13`, absent kernel headers, or NVIDIA package versions
disagreeing. Nix catches the missing-library case structurally. The rest are
assertions someone still has to write — the failure they prevent is a machine
that boots, reports no GPUs, and is silently mis-inventoried.

### Size: at parity, and the GPU stack dominates

    scout-store.squashfs  1396 MB   vs mkosi 1488 MB
    scout-loader.efi       375 MB   vs mkosi   74 MB

The rootfs — what a machine actually transfers per discovery — is slightly
smaller than mkosi's. The DCGM package alone is 959 MB of it, so the build
system barely moves the number either way.

Two earlier claims in this file were wrong and are corrected here: that NixOS
would be a size win (asserted before measuring), and that it was a regression
against a 1.24 GB baseline (measured against scout.cpio.zst, a stale artifact
from May; check mtimes in the blobs directory before quoting sizes).

Worth asking separately from the port: whether every scout boot needs the full
cuda13 plugin set, or whether diagnostics could be fetched only for nodes that
report GPUs. DCGM ships a cudaless plugin directory for that split.

### Resolved: scout does not run on DPUs

Scout runs on x86_64 and aarch64 *hosts*. It is not used on DPUs. The
`discovery-scout-aarch64-dpu` template in crates/ipxe-renderer/templates.yaml
boots carbide.efi/carbide.root with BlueField parameters (bfnet=, bfks=), which
is a different image from host scout and out of scope for this port.

What that settles:

  * **forge-scout deb is transitional after all.** It exists to install the
    agent into the mkosi scout initramfs. If NixOS scout replaces mkosi on both
    host architectures, the deb and the apt-repo generation in
    nix/container/boot-artifacts.nix go with it. An earlier note here claimed
    the deb was permanent because DPUs needed it; that was wrong, and it was a
    correction I made to a claim that had been right.
  * **forge-dpu deb stays.** setup-apt-repo-arm64 publishes two debs —
    forge-scout and forge-dpu — and only the second serves the DPU agent, which
    runs on a vendor OS carbide does not control. That deb and its repo are
    permanent regardless of what happens to scout.
  * **One update mechanism, not two.** The `nix copy` + switch-to-configuration
    story applies to every machine scout runs on, because they are all hosts
    where carbide owns the OS. There is no second, apt-driven update path to
    build.

The aarch64 host template is the same shape as x86 — `kernel .../aarch64/scout.efi`
with mac=, cli_cmd=, machine_id=, server_uri= — so the port cross-compiles
rather than needing a second design.

### Untested, and what to test first

Nothing has booted. Evaluation and a green build prove the module system is
satisfied and every reference resolves; they say nothing about whether a
machine comes up, enumerates GPUs and reports inventory.

In rough order of cost:

  1. `newrootfs=none` in QEMU. Exercises the loader's boot and its cmdline
     handling without needing the rootfs or real hardware. The loader stays
     put by design, so a shell prompt is a pass.
  2. The loader fetching a real scout-store over HTTP, still in QEMU. Proves
     the mount layout and the soft-reboot into ${toplevel}/init — the part
     that differs most from the Ubuntu image.
  3. Real hardware. Only this answers whether /run/opengl-driver/lib is
     populated with hardware.graphics off, which every DCGM plugin resolves
     libcuda.so.1 through, and whether the 590 driver behaves on the GPUs
     carbide qualifies against.

The aarch64 side has not been attempted at all. nix/os/scout.nix takes
forgeScout through specialArgs so it can be evaluated against a cross package
set, but nothing has tried it, and mft-x86_64.nix has no aarch64 twin for
scout (mft-aarch64.nix serves the DPU agent container).
