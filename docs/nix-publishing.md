# Nix Build Cache and Container Publishing

This document describes how carbide's Nix build artifacts are cached
and published. It covers:

- **Nix binary cache** — an S3 bucket hosting precompiled Nix store
  paths so developers and CI can skip expensive rebuilds
- **Container registry** — the Docker registry that receives per-service
  OCI images for Kubernetes deployment

These are two separate artifact stores for two different consumers.
The CA (central authority) workflow pushes to both; developers and
Kubernetes consume from one each.

## Concepts

### Nix binary cache

Nix derivations are content-addressed: identical inputs produce
identical output hashes. A binary cache is an HTTP-accessible store
of `hash → build output` entries. When Nix needs a derivation, it
checks the cache before building from source.

For carbide the key derivation to cache is `cargoArtifacts` — the
compiled external dependencies. It's slow to build (~15 minutes on a
cold runner) and rarely changes (only when `Cargo.lock` updates).
Caching it means source-only changes go from 15-minute full rebuilds
to 2-3 minute incremental rebuilds.

### Container registry

Each service has its own OCI image built by nix2container. Images are
loaded or pushed via `skopeo-nix2container` (the patched skopeo with
`nix:` transport support). The registry is unrelated to the Nix cache —
Kubernetes doesn't know about Nix, it just pulls container images by name.

## Required infrastructure

### 1. S3 bucket for Nix cache

**Name**: pick something like `carbide-nix-cache`
**Region**: pick one close to CI and developers
**Access model**:
- **Public read** — anyone can pull derivations. No credentials
  needed by clients. Safe because Nix verifies store path signatures
  before trusting content.
- **Restricted write** — only the CA has `s3:PutObject` via an IAM
  role or scoped user.

Example bucket policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::carbide-nix-cache/*"
    }
  ]
}
```

### 2. Signing keypair

Nix verifies store path contents against cryptographic signatures.
Anyone pulling from the cache must know the public key; only the CA
needs the secret key.

Generate once:

```sh
nix-store --generate-binary-cache-key \
  carbide-cache \
  ./carbide-cache.secret \
  ./carbide-cache.public
```

- **Public key** (`carbide-cache.public`) — paste into `flake.nix`
  under `nixConfig.extra-trusted-public-keys`. Committed to git.
- **Secret key** (`carbide-cache.secret`) — store in the CA's secret
  manager (Vault, AWS Secrets Manager, GitHub Actions secret). Never
  commit.

### 3. Container registry credentials

The CA needs push credentials for the target Docker registry
(e.g., `nvcr.io/<namespace>`). Store as a GitHub Actions secret or
equivalent.

### 4. Flake configuration

`flake.nix` declares the cache so developers pick it up automatically:

```nix
nixConfig = {
  extra-substituters = [
    "s3://carbide-nix-cache?region=us-west-2"
  ];
  extra-trusted-public-keys = [
    "carbide-cache:PUBLIC_KEY_GOES_HERE="
  ];
};
```

Developers get a one-time prompt to accept this config the first
time they run `nix build`. To skip the prompt on CI runners and
standardized dev environments, add to `/etc/nix/nix.conf`:

```
accept-flake-config = true
```

## CA workflow

The CA's job is to build release artifacts and publish them to both
stores. This happens in CI (e.g., a GitHub Actions workflow
triggered by push to `main` or a version tag).

Commands the CA runs (in order):

### Step 1 — Build the cache-warming derivation

```sh
nix build .#deps
```

This builds `cargoArtifacts` (all external deps). Typically takes
the longest. If `Cargo.lock` hasn't changed since the last run, it's
a cache hit and completes in seconds.

### Step 2 — Build the service containers

```sh
nix build .#carbide-api-container
nix build .#carbide-dns-container
# ... repeat per service, or build all via nix build .#<name>-container
```

Because `deps` is already in the local store from Step 1, each
container build only compiles workspace crates (~2-3 minutes).

### Step 3 — Push to the Nix cache

```sh
nix copy \
  --to "s3://carbide-nix-cache?region=us-west-2&secret-key=/path/to/carbide-cache.secret" \
  .#deps .#carbide-api-container .#carbide-dns-container
```

`nix copy` uploads each specified path **plus its entire closure**
(all transitive store path dependencies).

### Step 4 — Push to the container registry

Containers are pushed using the `copyToRegistry` helper baked into each
container's passthru. The flake's `nix2container-skopeo.nix` wraps
skopeo-nix2container for this:

```sh
# Load into local Docker daemon (also tags :latest)
nix run .#carbide-api-container-copy-to-docker

# Push directly to a registry (using the copyToRegistry passthru)
nix build .#carbide-api-container
$(nix eval --raw .#carbide-api-container.passthru.copyToRegistry)/bin/copy-to-registry
```

Or use skopeo directly against the nix2container JSON manifest:

```sh
result=$(nix build --print-out-paths .#carbide-api-container)
skopeo --insecure-policy copy \
  nix:$result \
  docker://nvcr.io/carbide-namespace/carbide-api:<tag>
```

## Developer workflow

Once the CA has pushed:

```sh
git pull
nix build              # Pulls precompiled deps from S3, builds only changed code
nix develop            # Drops into a dev shell with all tools
```

No authentication needed for pulls. The flake's `nixConfig`
handles substituter setup. First-time users see a prompt; users
with `accept-flake-config = true` get it transparently.

## Flake additions needed

The `nixConfig` block (substituter + public key) still needs to be added
to `flake.nix` once the signing keypair and S3 bucket are provisioned:

```nix
nixConfig = {
  extra-substituters = [ "s3://carbide-nix-cache?region=us-west-2" ];
  extra-trusted-public-keys = [ "carbide-cache:PUBLIC_KEY_GOES_HERE=" ];
};
```

## Security notes

- **Secret keys must not be committed.** Use GitHub Actions secrets,
  Vault, or AWS Secrets Manager.
- **Public-read cache is safe.** Nix verifies signatures before
  trusting content, so cache tampering is detectable. Anyone with
  the store hash can download — which isn't a threat because the
  derivations are built from source already in this git repo.
- **Per-environment trust keys.** If you add a staging cache, give
  it a separate keypair so staging artifacts can't be signed with
  production keys.

## Cost considerations

S3 costs are dominated by egress. For a public-read cache with
moderate CI and developer usage, expect a few dollars per month in
storage + a few dollars per month in egress (depending on build
activity). To control costs:

- **Lifecycle policy**: delete objects older than N days (Nix
  cache misses are cheap — just trigger a rebuild)
- **CloudFront**: caches S3 at edge, reduces direct S3 egress,
  cheaper for high-traffic scenarios
- **Regional buckets**: place near primary CI runner region

## What's missing / follow-up work

- Signing keypair not yet generated
- S3 bucket not yet provisioned
- `nixConfig` block not yet added to `flake.nix`
- GitHub Actions workflow not yet written
- IAM policy for CA write access not yet defined
- Retention/lifecycle policy not yet decided
