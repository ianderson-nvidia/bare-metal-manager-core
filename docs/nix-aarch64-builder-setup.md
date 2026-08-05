# aarch64 Nix builder setup (EC2 Graviton)

How to provision an aarch64 EC2 instance as a Nix distributed builder
for `nix build .#packages.aarch64-linux.<...>` from your x86 dev machine.

Single-builder setup. For multi-builder pools and parallelism, see
[SESSION.md](../SESSION.md)'s "Distributed builds — multi-builder
pool" section.

## Do you need this?

A builder is optional. There are three ways to produce an aarch64 image,
and they differ in what they cost rather than in what they produce:

| | invocation | needs | substitutes from cache.nixos.org |
|---|---|---|---|
| Remote builder | `just image-aarch64 <name>` | this guide | yes |
| binfmt emulation | `just image-aarch64 <name>` | `qemu-user-static` + `extra-platforms` | yes |
| Cross-compile | `just image-aarch64-cross <name>` | nothing | **no** |

The first two build the *same* derivations — the ones nixpkgs' Hydra has
already built for aarch64 — so the whole base arrives prebuilt and only
carbide's own packages are compiled. Cross-compiling produces different
store paths that nobody upstream has ever built, so glibc, gcc, systemd
and the kernel are compiled from source every time the store is empty.

Prefer a builder or binfmt. Cross-compiling is the fallback for working
offline or with no aarch64 execution available at all.

### binfmt, if you would rather not run a builder

Two things are needed, and having the binfmt handlers registered is only
the first. Install `qemu-user-static` (or your distribution's equivalent),
then tell Nix it is *allowed* to build for the platform — registered
handlers alone are not enough, and without this you get:

```
error: Cannot build '/nix/store/....drv'.
       Reason: platform mismatch
       Required system: 'aarch64-linux'
       Current system: 'x86_64-linux'
```

A trusted user (`trusted-users` in `/etc/nix/nix.custom.conf`) can set it
in `~/.config/nix/nix.conf`; otherwise it goes in the system config:

```
extra-platforms = aarch64-linux i686-linux x86_64-v1-linux x86_64-v2-linux x86_64-v3-linux x86_64-v4-linux
```

The trailing entries are Nix's auto-detected defaults on an x86_64 host,
not previous configuration — `extra-platforms` replaces rather than
appends, so restate them. Note that `nix config show extra-platforms`
reports the client's view, so verify by building rather than by reading:

```
nix build --impure --expr \
  '(import <nixpkgs> { system = "aarch64-linux"; }).runCommand "p" {} "uname -m > $out"'
```

The output should contain `aarch64`, and the log should show the aarch64
stdenv being *copied from cache.nixos.org* rather than built — that is the
property that makes emulation cheap.

`--extra-platforms aarch64-linux` on the command line does the same thing
for a one-off, which is the quickest way to confirm the setup works before
making it permanent.

Emulated compilation runs roughly 5–20× slower than native, but that
only applies to what actually has to be built — the kernel is downloaded,
not emulated. A small number of packages misbehave under `qemu-user`;
those are the case for a real builder.

On NixOS the equivalent is `boot.binfmt.emulatedSystems = [ "aarch64-linux" ];`.

### Removing a builder

A `builders =` line naming a host that no longer exists does not fail
gracefully — aarch64 builds try to offload to a dead address. Delete the
line from `/etc/nix/nix.custom.conf` when decommissioning the instance.

> **Determinate Nix config layout:** This guide assumes you're using
> Determinate Nix (the installer used below). Determinate splits its
> config across two files:
>
> - `/etc/nix/nix.conf` — auto-generated, marked "do not modify".
> - `/etc/nix/nix.custom.conf` — user-editable; included by the main
>   file via `!include nix.custom.conf`.
>
> All edits in this guide go to `nix.custom.conf` (or to your user's
> `~/.config/nix/nix.conf`). On stock multi-user Nix, edit
> `/etc/nix/nix.conf` directly instead.

## EC2 instance choice

| Option | vCPU | RAM | Sustained perf? | $/hr (on-demand) |
|---|---|---|---|---|
| t4g.xlarge | 4 | 16 GB | No (CPU-credit throttle to 40% baseline after ~10 min) | $0.067 |
| **c7g.xlarge** (recommended) | 4 | 8 GB | Yes | $0.07 |
| c7g.2xlarge | 8 | 16 GB | Yes | $0.14 |

**Don't use t4g for builder workloads** — burstable instances throttle
under sustained compile load. c7g is the same price point with
sustained perf and faster Graviton 3 cores.

Other launch settings:

- **Root volume: minimum 50 GB.** Default 8 GB fills up during the
  first cold Rust build. The workspace closure is ~10-15 GB with
  headroom needed for build temp dirs.
- **Security group: inbound TCP 22 from your dev box's public IP.**
  Otherwise SSH and `ssh-keyscan` will hang.
- **AMI: Ubuntu 24.04 LTS** (or any modern Linux with user namespaces
  enabled — Nix sandbox needs them).

## On the new EC2 instance

```sh
# 1. Install Nix (multi-user, via Determinate installer)
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix \
  | sh -s -- install --determinate

# Re-source so `nix` is on PATH in this shell
source /etc/profile.d/nix-daemon.sh   # or: log out + back in

# 2. Add ubuntu to trusted-users (required for distributed builds —
#    untrusted users can't override builders config or upload derivations)
sudo bash -c "echo 'trusted-users = root ubuntu' >> /etc/nix/nix.custom.conf"

# 3. Set cores = 0 so per-derivation builds use all vCPUs.
#    Default is 1, which underutilizes a 4+ vCPU instance for kernel
#    compiles and similar single-derivation big workloads.
sudo bash -c "echo 'cores = 0' >> /etc/nix/nix.custom.conf"

# 4. Restart nix-daemon to pick up the config changes
sudo systemctl restart nix-daemon

# 5. Verify
nix config show | grep -E '^(trusted-users|cores)'
# expected:
#   cores = 0
#   trusted-users = root ubuntu
```

## On your local machine

```sh
# 6. Update the builders line in /etc/nix/nix.custom.conf to point at the
#    new IP. The line looks like:
#      builders = ssh-ng://ubuntu@<ip> aarch64-linux <ssh-key> 8 1 nixos-test,benchmark,big-parallel,kvm
#
#    Use absolute paths in the config — nix-daemon runs as root and
#    can't expand `~` or use your user's ~/.ssh/config.
sudo nvim /etc/nix/nix.custom.conf

# Recommended line (substitute the new IP):
#   builders = ssh-ng://ubuntu@<new-ec2-ip> aarch64-linux /home/ian/.ssh/ian-aws.pem 8 1 nixos-test,benchmark,big-parallel,kvm
#   builders-use-substitutes = true

# 7. Seed root's known_hosts for the new EC2.
#    nix-daemon's spawned ssh runs as root; it has its own
#    /root/.ssh/ (separate from your user's), and `BatchMode=yes`
#    means no interactive host-key trust prompts. Without seeding,
#    you get "Host key verification failed" on first build.
ssh-keyscan -H <new-ec2-ip> | sudo tee -a /root/.ssh/known_hosts

# 8. Restart local nix-daemon so it re-reads builders config
sudo systemctl restart nix-daemon

# 9. Verify the SSH path works as root would invoke it
sudo ssh -i /home/ian/.ssh/ian-aws.pem -o BatchMode=yes ubuntu@<new-ec2-ip> uname -m
# expected: aarch64

# 10. Verify nix can reach the builder
nix store info --store ssh-ng://ubuntu@<new-ec2-ip>
# expected:
#   Store URL: ssh-ng://ubuntu@<new-ec2-ip>
#   Version: 2.x.x
#   Trusted: 1
```

`Trusted: 1` is the green light. `Trusted: 0` means step 2 (trusted-users
on the EC2) didn't take — re-run step 2 + 4.

## Smoke test

```sh
nix build --impure --expr '
  let pkgs = import <nixpkgs> { system = "aarch64-linux"; };
  in pkgs.hello'

file result/bin/hello
# expected: ELF 64-bit LSB ... ARM aarch64 ...
```

If `result/bin/hello` is an aarch64 ELF (and you're on an x86 dev box),
the distributed build path is working end-to-end.

## SSH bypass for noisy agents

If your local user has many keys in ssh-agent (typical work laptop
with github + multiple internal keys), you may hit
`Too many authentication failures` because sshd cuts off after
`MaxAuthTries=6` failed offers. Two fixes:

**Option A — restrict in `~/.ssh/config`:**

```
Host <new-ec2-ip>
  User ubuntu
  IdentityFile ~/.ssh/ian-aws.pem
  IdentitiesOnly yes
  IdentityAgent none
```

**Option B — bypass agent for one-off commands:**

```sh
ssh -i ~/.ssh/ian-aws.pem \
    -o IdentityAgent=none \
    -o IdentitiesOnly=yes \
    ubuntu@<ip>
```

For nix-daemon's own ssh invocations (running as root with no agent
inherited), this isn't an issue — the bypass matters only for your
interactive `ssh` and `ssh-keyscan` commands.

## Daily-use commands

After setup, the builder is invisible — `nix build` automatically
dispatches aarch64 derivations to it:

```sh
# Cross-compiled aarch64 Rust binaries (built on the aarch64 builder)
nix build .#packages.aarch64-linux.forge-dpu-agent
nix build .#packages.aarch64-linux.forge-dhcp-server
nix build .#packages.aarch64-linux.carbide-fmds
nix build .#packages.aarch64-linux.carbide-scout-aarch64

# aarch64 containers (native nix2container build on aarch64 builder)
nix build .#packages.aarch64-linux.carbide-dhcp-container
```

From an x86_64 host, `nix build .#forge-dpu-agent` cross-compiles
directly without needing to address the aarch64 system explicitly —
the flake's x86_64-linux packages block includes the aarch64 binaries
via `mkCrossCrateBinary`.

The first build of any aarch64 target on a fresh EC2 recompiles from
source (no `/nix/store` cache yet). Subsequent builds use the EC2's
local store and are fast. To preserve that cache across instance
restarts, **stop** the instance rather than terminate it (EBS
persists, costs ~$5/month for 50 GB).

## Persistent cross-instance cache

If you'll spin up multiple aarch64 builders (CI runners, replacement
EC2s) and want to avoid recompiling on every fresh instance, set up
a self-hosted binary cache:

- [attic](https://github.com/zhaofengli/attic) — popular self-hosted
  Nix binary cache server
- [cachix](https://cachix.org) — managed binary cache
- S3-backed cache via `nix copy --to s3://...`

Pushing your built artifacts to a shared cache lets every consumer
substitute instead of recompile. Particularly valuable for the first cold build of the aarch64 Rust
workspace (~15 min on c7g.xlarge).

## Troubleshooting

**`Failed to find a machine for remote build!` despite the builder
being listed:** check the system field. nix doesn't validate the
system string — `aarch-linux` (typo) silently won't match
`aarch64-linux`. Look for `aarch64-linux` exactly.

**`failed to start SSH master connection`:** root can't reach the
builder. Run `sudo ssh ...` as root with `BatchMode=yes` to see the
real error — typically host-key verification (step 7) or wrong key
path.

**`warning: ignoring the client-specified setting 'builders'`:** the
local user isn't in the local `/etc/nix/nix.custom.conf`'s `trusted-users`.
Add yourself there too:

```sh
sudo bash -c "echo 'trusted-users = root $USER' >> /etc/nix/nix.custom.conf"
sudo systemctl restart nix-daemon
```

**Most active processes on the EC2 are nix-daemon, no compilers:**
the build is in either (a) closure copy from local → EC2 over SSH or
(b) substitute pull from cache.nixos.org. Both are network-bound
phases that look idle. Watch `du -sh /nix/store` on the EC2 — if
it's growing, the build is making progress and the CPU-bound phase
is coming.

## Memory ceiling — `max-jobs` vs `cores`

The c7g.xlarge has only **8 GB RAM**. The larger carbide crates compile
rustc with 2-3 GB peak per invocation. Easy to OOM the nix-daemon and crash
the build with `Nix daemon disconnected unexpectedly`.

Two knobs control parallelism, and they're often confused:

- **`max-jobs`** (local-side, 4th field of `builders =`): how many
  derivations to dispatch **in parallel** to the remote builder.
  Multiplies memory cost — each derivation runs its own rustc.
- **`cores`** (remote-side, `/etc/nix/nix.custom.conf`): how many
  threads each derivation may use internally (`cargo build -j`,
  `make -j`). Increases CPU utilisation but adds little memory.

**Symptom → knob:**
- OOM / daemon-disconnect / SIGKILL on rustc → lower `max-jobs`.
- Single rustc takes forever, lots of idle cores → raise `cores`.

For c7g.xlarge (4 vCPU, 8 GB), `max-jobs = 2` and `cores = 3` is
a good starting point: 2 derivations in parallel, each using up to
3 threads. Fits comfortably in 8 GB for carbide-scale workspaces.

Edit `builders =` in your **local** `/etc/nix/nix.custom.conf`,
restart `nix-daemon`, and you're done — no rebuild of the EC2 needed.

### Belt-and-suspenders: swap on the builder

If a single fat rustc invocation still squeezes memory at
`max-jobs = 2`, an 8 GB swapfile on the Graviton lets it spill
rather than die:

```sh
ssh admin@<ip> << 'EOF'
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
EOF
```

Adds ~8 GB of EBS-backed swap. Compiles spilling to swap are
slower but won't crash. The `Under memory pressure, flushing
caches` journal messages on the builder are a leading indicator
that you'll OOM without swap.
