# ==============================================================================
# Build definition for carbide-dhcp.
#
# This crate links against Kea's C++ libraries (libkea-dhcp, libkea-hooks,
# libkea-asiolink, etc.) via its build.rs.
#
#   1. The dhcp build.rs reads KEA_INCLUDE_PATH and KEA_LIB_PATH to find
#      Kea headers and libraries. These have to point at the Nix store
#      paths, not /usr/include/kea like the Debian default.
#
#   2. Kea 3.x renamed libkea-dhcp++.so to libkea-dhcp.so, but the
#      build.rs in this crate still emits `cargo:rustc-link-lib=kea-dhcp++`.
#      The postConfigure hook below builds a writable lib directory
#      containing all Kea libs plus a libkea-dhcp++.so symlink pointing
#      at libkea-dhcp.so, then redirects KEA_LIB_PATH there so the
#      linker finds the expected name.
# ==============================================================================
{
  pkgs,
  craneLib,
  commonArgs,
  cargoArtifacts,
  ...
}:

craneLib.buildPackage (
  commonArgs
  // {
    pname = "carbide-dhcp";
    inherit cargoArtifacts;
    cargoExtraArgs = "--package carbide-dhcp";
    doInstallCargoArtifacts = false;

    # carbide-dhcp builds the Kea hook plugin (a cdylib), so it links
    # the full Kea C++ stack plus its boost/grpc transitive C++ deps.
    # openssl is here because tonic-prost / tls is in the dep graph.
    #
    # stdenv.cc.cc.lib provides libgcc_s.so.1 for Rust panic unwinding;
    # boost.dev/grpc would pull it in transitively, but listing it
    # explicitly makes the dep visible at this layer and survives any
    # future trimming of the C++ deps.
    buildInputs = with pkgs; [
      boost.dev
      grpc
      kea
      openssl
      stdenv.cc.cc.lib
    ];

    postConfigure = ''
      # Kea 3.x renamd libkea-dhcp++.so to libkea-dhcp.so but the dhcp crate
      # build.rs still links against kea-dhcp++
      mkdir -p $TMPDIR/kea-lib
      ln -sf ${pkgs.kea}/lib/libkea-*.so* $TMPDIR/kea-lib
      ln -sf ${pkgs.kea}/lib/libkea-dhcp.so $TMPDIR/kea-lib/libkea-dhcp++.so
      export KEA_LIB_PATH="$TMPDIR/kea-lib"
    '';
    KEA_INCLUDE_PATH = "${pkgs.kea}/include/kea";
    KEA_LIB_PATH = "${pkgs.kea}/lib";

  }
)
