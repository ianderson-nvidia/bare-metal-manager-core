# `nix run .#<name>-copy-to-docker` — load a container into the local Docker
# daemon.
#
# nix2container images are not tarballs; they are a JSON manifest plus a set of
# store paths. The copyToDockerDaemon helper it attaches to each image shells
# out to a patched skopeo (see nix/container/nix2container-skopeo.nix) that
# understands the `nix:` transport and can therefore stream those store paths
# straight into the daemon without ever materialising an intermediate archive.
#
# Only the amd64 images get an app. Loading an arm64 image into an x86 daemon
# produces something that cannot run, so the caller is better served by an
# explicit `nix build .#<name>-arm64` and a deliberate push.
{
  pkgs,
  # amd64 container derivations, keyed by image name.
  containers,
}:

pkgs.lib.mapAttrs' (
  name: container:
  pkgs.lib.nameValuePair "${name}-copy-to-docker" {
    type = "app";
    program = "${container.passthru.copyToDockerDaemon}/bin/copy-to-docker-daemon";
  }
) containers
