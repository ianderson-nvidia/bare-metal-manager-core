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

## mkosi → NixOS scout: state of the port

Two flake targets mirror the two mkosi profiles. Both build; neither has
booted.

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

### Open question: is DPU scout a deb, and does that make the deb permanent?

Scout runs on x86_64 hosts, aarch64 hosts, and DPUs. The DPU runs a vendor
BlueField/DOCA image that carbide does not control, so there is no prospect of
NixOS owning that OS and no Nix store to copy a closure into.

crates/ipxe-renderer/templates.yaml has three discovery templates, and the DPU
one is a different image entirely:

    discovery-scout-x86_64        kernel .../x86_64/scout.efi
    discovery-scout-aarch64       kernel .../aarch64/scout.efi        (host)
    discovery-scout-aarch64-dpu   kernel .../aarch64/carbide.efi
                                  imgfetch .../aarch64/carbide.root
                                  bfnet=, bfks=<cloudinit>/user-data

So the aarch64 *host* path is the same shape as x86 and should port the same
way. The DPU path is BlueField-specific and is not a NixOS system.

**To confirm:** how forge-scout actually reaches a DPU. If it is the
forge-scout arm64 deb installed into the DPU image from the apt repo we
publish, then:

  * nix/deb/debs.nix and the apt repo generation in
    nix/container/boot-artifacts.nix are permanent interfaces, not mkosi-era
    scaffolding awaiting removal. An earlier note in this file said the deb
    goes away with mkosi; that is wrong for aarch64 if this is how DPUs are
    served.
  * DPU scout updates stay apt-driven against that repo. The `nix copy` +
    switch-to-configuration story discussed for hosts does not apply there,
    because it needs a Nix store on the target.
  * carbide ends up with two update mechanisms by necessity — closure-based
    for hosts, package-based for DPUs — and check-scout-updates only covers
    the host side today.

Worth checking at the same time whether carbide.efi/carbide.root are built by
the same mkosi profiles as host scout or by the BFB flow, since that decides
whether the DPU path is even in scope for the mkosi retirement.

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
