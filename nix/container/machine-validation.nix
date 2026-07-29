# File trees for the machine-validation container images.
#
# Replaces dev/docker/Dockerfile.machine-validation-{runner,config,config-aarch64}.
# Those images did no compilation — they layered static files onto the runtime
# container and (for the config image) generated a tarball of the config tree.
#
# Both outputs are architecture-independent; only the container that wraps them
# differs per arch, so the same derivation feeds the amd64 and arm64 images.
{
  pkgs,
  configDir,
  imagesDir,
  scriptsDir,
}:

{
  # machine-validation-runner: just the scripts tree.
  # The image has no entrypoint — callers exec into it.
  runnerFiles = pkgs.runCommand "machine-validation-runner-files" { } ''
    mkdir -p $out/machine-validation
    cp -r ${scriptsDir} $out/machine-validation/scripts
  '';

  # machine-validation-config: the config and images trees, plus a tarball of
  # the config tree placed inside it.
  #
  # The Dockerfile built the tarball in /tmp and copied it back in afterwards so
  # that config.tar would not contain itself. We get the same result by taring
  # from the pristine store path instead. The tar flags pin ordering, mtime, and
  # ownership so the output is bit-reproducible across builds.
  configFiles = pkgs.runCommand "machine-validation-config-files" { } ''
    mkdir -p $out/machine-validation
    cp -r ${configDir} $out/machine-validation/config
    cp -r ${imagesDir} $out/machine-validation/images

    # Store paths are read-only; we need to write config.tar into config/.
    chmod -R u+w $out/machine-validation/config

    tar -cf $out/machine-validation/config/config.tar \
      --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
      -C ${configDir} .
  '';
}
