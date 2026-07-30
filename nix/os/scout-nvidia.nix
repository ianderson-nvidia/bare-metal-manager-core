# GPU driver and validation stack for the scout discovery environment.
#
# Scout is not only a hardware inventory tool — on GPU nodes it runs DCGM
# diagnostics, which means the proprietary driver has to be loaded and the
# NVLink fabric brought up before forge-scout reports anything useful. That is
# what makes this the substantial half of the mkosi port; everything else in
# scout.nix is tool packaging.
#
# Kept separate from scout.nix so a GPU-less variant can drop it, and so the
# driver's build cost is visible rather than buried in a general config.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  # NVIDIA's published DCGM packages, carrying the cuda13 plugin set.
  dcgm = import ../third-party/dcgm-deb.nix { inherit pkgs; };

  # Internode Memory Exchange. Kept in lockstep with the driver — see the
  # branch note below for why the scope is pinned rather than left at the
  # cudaPackages default, which tracks CUDA 12 and a 575 IMEX.
  imex = pkgs.cudaPackages_13_1.imex;

  # mkosi.extra/opt/forge/dcgmi-pre.sh, which is a bare `nvidia-smi`. Running
  # it first initialises the driver and creates the /dev/nvidia* nodes, so the
  # dcgmi call that follows finds a ready device rather than racing the
  # driver's lazy first-use setup.
  dcgmiPre = pkgs.writeShellScriptBin "dcgmi-pre" ''
    exec ${config.hardware.nvidia.package.bin}/bin/nvidia-smi
  '';
in

{
  # The datacenter driver, DCGM, and CUDA are all unfree.
  nixpkgs.config.allowUnfree = true;

  # ==========================================================================
  # Driver
  #
  # `datacenter.enable` selects the data center driver rather than the desktop
  # one and brings up nvidia-fabricmanager, which is required on NVLink/NVSwitch
  # systems before the GPUs are usable. On a desktop driver the GPUs would
  # enumerate but the fabric would stay down.
  #
  # The 590 datacenter branch rather than the 580 the mkosi profile pins.
  # IMEX negotiates the NVLink fabric between nodes and refuses to run against
  # a driver it does not recognise, so driver and IMEX have to agree; on 580
  # they do not, in either direction:
  #
  #   dc_580  580.159.03   imex 580.126.20   mismatched (and mkosi pins .16)
  #   dc_590  590.48.01    imex 590.48.01    driver, fabricmanager and IMEX agree
  #
  # 595 also lines up, but only via `beta` — NVIDIA's beta channel, and not a
  # dc_* datacenter package. 590 is the newest branch where all three pieces
  # are aligned on a datacenter driver.
  # ==========================================================================
  hardware.nvidia.datacenter.enable = true;
  hardware.nvidia.package = config.boot.kernelPackages.nvidiaPackages.dc_590;

  # The open kernel modules, matching the mkosi profile's
  # nvidia-driver-580-open / nvidia-dkms-580-open. They are the supported
  # choice on data center parts from Turing on, and unlike the closed modules
  # they are source-built against this kernel rather than needing a prebuilt
  # blob for it. There is no default for this option, so it has to be stated.
  hardware.nvidia.open = true;

  # nouveau binds the same PCI IDs and must lose the race, or the proprietary
  # module fails to load. Mirrors mkosi.extra/etc/modprobe.d/blacklist.conf.
  boot.blacklistedKernelModules = [ "nouveau" ];

  # hardware.graphics is off in scout.nix — these GPUs do no rendering, and
  # enabling it would pull Mesa and LLVM into an image that boots over HTTP.
  # The datacenter driver does not need it; compute and DCGM go through
  # /dev/nvidia* directly.

  # ==========================================================================
  # DCGM
  #
  # From NVIDIA's Debian packages rather than nixpkgs' `dcgm`. nixpkgs builds
  # 4.3.1 from source, whose CMake only knows about CUDA 12 and so ships
  # plugins/cuda12/BwChecker_12; carbide qualifies against cuda13. See
  # nix/third-party/dcgm-deb.nix for why the source route was not taken.
  #
  # nixpkgs has no NixOS module for DCGM either way, so the host engine gets a
  # unit here. forge-scout shells out to dcgmi, which talks to this daemon over
  # its local socket; without it every diagnostic returns a connection error
  # rather than a result.
  # ==========================================================================
  environment.systemPackages = [
    dcgm
    dcgmiPre
    imex
    # nvidia-smi and friends. The driver package's bin output is what
    # forge-scout uses to read driver version and GPU topology.
    config.hardware.nvidia.package.bin
    # nvswitch-audit and nv-fabricmanager, both present in the mkosi image's
    # /usr/bin. The datacenter module puts only nvidia_x11.bin on PATH and
    # starts the fabricmanager daemon by store path, so without this the audit
    # tool — which reports NVSwitch topology and link state, and is the reason
    # a fabric-attached machine can be inventoried at all — is unreachable.
    config.hardware.nvidia.package.fabricmanager
  ];

  # `systemctl enable nvidia-imex` in the mkosi postinst. IMEX exports GPU
  # memory across nodes over the NVLink fabric, so it only has anything to do
  # once fabricmanager has finished training that fabric — starting earlier
  # makes it exit rather than wait.
  #
  # The upstream package ships no unit, only the binary and a config file, so
  # the config path is passed explicitly rather than relying on /etc.
  systemd.services.nvidia-imex = {
    description = "NVIDIA Internode Memory Exchange";
    wantedBy = [ "multi-user.target" ];
    after = [ "nvidia-fabricmanager.service" ];
    wants = [ "nvidia-fabricmanager.service" ];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${imex}/usr/bin/nvidia-imex -c ${imex}/etc/nvidia-imex/config.cfg";
      # A single-node machine has no peers to exchange with, and scout runs on
      # plenty of those. Failing to start is expected there, not an error worth
      # restarting into a loop over.
      Restart = "no";
    };
  };

  systemd.services.nv-hostengine = {
    description = "NVIDIA DCGM host engine";
    wantedBy = [ "multi-user.target" ];
    # The engine enumerates GPUs at start, so it has to come up after the
    # driver modules are loaded and after fabricmanager has finished training
    # the NVLink fabric — otherwise it caches an incomplete topology.
    after = [
      "systemd-modules-load.service"
      "nvidia-fabricmanager.service"
    ];
    wants = [ "nvidia-fabricmanager.service" ];
    serviceConfig = {
      Type = "forking";
      ExecStart = "${dcgm}/bin/nv-hostengine";
      ExecStop = "${dcgm}/bin/nv-hostengine --term";
      Restart = "on-failure";
    };
  };

  # ==========================================================================
  # Build-time assertions
  #
  # The mkosi postinst failed the build when a driver piece was missing or
  # versions disagreed, because the failure mode otherwise is a machine that
  # boots, reports no GPUs, and is silently mis-inventoried. Nix catches the
  # missing-library case structurally, but not these.
  # ==========================================================================
  assertions = [
    {
      # Not a branch check: IMEX and the driver have to agree exactly, and the
      # cudaPackages scope supplying IMEX is easy to change without noticing
      # that it moved off the driver's version. The failure this prevents is
      # IMEX declining to start on a fabric-attached node, which looks like a
      # hardware fault rather than a packaging mistake.
      assertion = imex.version == config.hardware.nvidia.package.version;
      message = ''
        nvidia-imex ${imex.version} does not match the driver
        ${config.hardware.nvidia.package.version}. IMEX refuses to run against
        a driver it does not recognise. Pick the cudaPackages scope whose imex
        matches, or move the driver to a branch that has one:
          dc_580 -> 580.159.03, imex 580.126.20   (no match)
          dc_590 -> 590.48.01,  imex 590.48.01    (cudaPackages_13_1)
          beta   -> 595.45.04,  imex 595.45.04    (cudaPackages_13_2)
      '';
    }
    {
      assertion = !config.hardware.graphics.enable;
      message = ''
        hardware.graphics pulls Mesa and LLVM into the scout image for no
        benefit: these GPUs render nothing. If something now needs it, weigh
        the size against what boots over HTTP per machine.
      '';
    }
  ];
}
