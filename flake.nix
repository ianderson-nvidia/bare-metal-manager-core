/*
  BUILDING TARGETS
  ================

  List every available build target:

    nix flake show

  Build a specific target (output lands in ./result):

    nix build .#<name>

  Common examples:

    nix build .#carbide-api                    # native x86_64 binary
    nix build .#carbide-api-container          # x86_64 OCI container image
    nix build .#carbide-api-container-arm64    # arm64 OCI container image
    nix build .#carbide-dhcp                   # Kea hook library (libdhcp.so)
    nix build .#carbide-dhcp-container         # x86_64 DHCP container
    nix build .#forge-scout-deb                # .deb package (x86_64)
    nix build .#ipxe-efi-x86                   # iPXE EFI bootloader

  Load a container into the local Docker daemon:

    nix run .#carbide-api-container.copyToDockerDaemon

  Enter the dev shell (Rust toolchain + all build tools):

    nix develop

  Nix language quick reference
  Full docs: https://nix.dev/tutorials/nix-language
             https://nix.dev/manual/nix/2.26/language/
  nixpkgs lib search: https://noogle.dev

  KEY PROPERTIES
  ==============

  1. Everything is an expression — there are no statements. `if`, `let`, and
     `with` all produce values. In imperative languages `if` executes code; in
     Nix it evaluates to whichever branch was taken:

     buildInputs = if pkgs.stdenv.isLinux then [ pkgs.libudev ] else [];

     `let` evaluates to whatever follows `in`:

     let
       x = 5;
       label = if x > 3 then "big" else "small";
     in
     label  # -> "big"

  2. Immutable — bindings cannot be changed after they are set. `//` does not
     mutate an attrset; it produces a new one with the right-hand side winning
     on duplicate keys:

     { a = 1; b = 2; } // { b = 99; }  # -> { a = 1; b = 99; }

  3. Lazy — expressions are only evaluated when their value is needed.
     Evaluating a flake (e.g. `nix flake show`) does not build anything; a
     derivation is only realised when you explicitly request it (`nix build`).
     This is why a flake with hundreds of packages doesn't try to build them
     all up front.

  4. Functional — functions are first-class values. `rustToolchainFor` below is
     a plain binding that happens to hold a function.

  TYPES
  =====
  string, integer, boolean, null, list, attrset, path, function, derivation.
  There is no type system; type errors surface at evaluation time.

  FUNCTIONS
  =========
  Functions are defined with a colon — `argument: body`:

    x: x + 1          # anonymous function
    (x: x + 1) 5      # -> 6

  Bind a name in a `let`:

    let addOne = x: x + 1;
    in addOne 5        # -> 6

  Multiple arguments use currying — each `:` adds one parameter:

    let add = x: y: x + y;
    in add 3 4         # -> 7

  Attrset destructuring (the dominant pattern in nixpkgs and flakes):

    let
      say = { name, statement }: "${name}. ${statement}!";
    in
    say { name = "Joseph Miller"; statement = "it reaches out"; }

  `{ pkgs, system, version, ... }: ...` is a function that destructures named
  fields from an attrset. `...` means "accept extra fields I haven't named".

  COMMON SYNTAX
  =============

  inherit — shorthand for copying a binding by name:
    inherit pkgs;            # same as: pkgs = pkgs;
    inherit (foo) a b;       # same as: a = foo.a; b = foo.b;

  with — bring all attributes of a set into scope for one expression:
    with pkgs; [ curl openssl tpm2-tools ]
    # equivalent to: [ pkgs.curl pkgs.openssl pkgs.tpm2-tools ]

  import — evaluate a .nix file, optionally calling it as a function:
    import ./nix/go/rest-api.nix { inherit pkgs version; }
    # Reads the file, which returns a function, then calls it with the attrset.

  Paths vs strings — path literals (no quotes) are copied into the Nix store
  and resolve relative to the file they appear in:
    src = ./rest-api;      # path — added to the store, works as a source
    src = "./rest-api";    # string — NOT a path; will fail as a derivation src

  String interpolation uses ${ }:
    "--prefix=${pkgs.openssl}/lib"

  FLAKE STRUCTURE
  ===============
  A flake is an attrset with `description`, `inputs`, and `outputs`. The
  `outputs` attribute is a function that receives the resolved inputs and
  returns the flake's public attrset (packages, devShells, apps, etc.).
  The body of `outputs` is one large `let ... in` block — all the derivations
  and helper functions in this file live in that `let`.
*/


{
  description = "Infra Manager (Carbide) — Nix build infrastructure";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    # crane: two-phase Rust build caching (deps separate from source).
    crane.url = "github:ipetkov/crane";

    # flake-utils: helpers for multi-system outputs (x86_64, aarch64).
    flake-utils.url = "github:numtide/flake-utils";

    # nix2container: OCI-native image metadata with direct copy helpers.
    nix2container = {
      url = "github:nlewo/nix2container";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # rust-overlay: provides exact Rust toolchain versions.
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    bombon = {
      url = "github:nikstur/bombon";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      flake-utils,
      nix2container,
      rust-overlay,
      bombon,
    }:
    # eachSystem iterates over an explicit list of systems, evaluating the
    # function for each, and merges the results into the flake outputs attrset.
    # https://github.com/numtide/flake-utils
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ] (
      system:
      let
        # Instantiate nixpkgs for this system. `import nixpkgs { system; }` is
        # how you get a package set bound to a specific platform — every
        # derivation in `pkgs` will be built for and run on `system`.
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
          # overlays are a list of functions that patch or extend a package set.
          overlays = [
            rust-overlay.overlays.default
          ];
        };

        isLinux = pkgs.stdenv.isLinux;

        # Crane wants a function over the package set `p` rather than a pre-built
        # derivation so it can splice the toolchain through build/host/target
        # package sets correctly when cross-compiling.
        # https://github.com/oxalica/rust-overlay
        rustToolchainFor =
          p:
          p.rust-bin.stable."1.95.0".default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
            ];
            targets = [
              "aarch64-unknown-linux-gnu"
            ];
          };

        # Initialize crane with the custom Rust toolchain above. All craneLib.*
        # calls in this file use this instance.
        # https://crane.dev/API.html#cranemklib
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchainFor;

        # nix2container library — provides buildImage and the OCI layer-diffing
        # machinery used by mkContainer.
        # https://github.com/nlewo/nix2container
        nix2containerLib = nix2container.packages.${system}.nix2container;

        # Skopeo-based copy helpers: copyToDockerDaemon, copyToRegistry,
        # copyToRegistryMultiArch. Uses a patched skopeo with nix: transport
        # so images can be copied directly from the Nix store.
        containerCopyHelpers = import ./nix/container/nix2container-skopeo.nix {
          inherit pkgs;
          skopeoNix2container = nix2container.packages.${system}.skopeo-nix2container;
        };

        # ====================================================================
        # Version assertions for packages with ABI-sensitive runtime coupling.
        #
        # libdhcp.so (the Kea hook) is compiled against libkea-*.so with
        # ABI-versioned SONAME entries. A Kea major version bump changes those
        # SONAMEs, breaking hook loading at runtime with an opaque dlopen error.
        # The assertion catches this during `nix flake update` before it ships.
        # To accept a new version: verify hook compatibility, then update the
        # expected string below.
        # ====================================================================
        _keaVersionCheck = assert pkgs.kea.version == "3.2.0"
          || builtins.throw ''
              kea version changed to ${pkgs.kea.version}.
              libdhcp.so links against libkea-*.so — verify hook ABI compatibility
              before accepting. Then update the assertion in flake.nix.
            '';
          true;

        # libudev-zero is a drop-in libudev replacement linked into every Rust
        # binary via allBuildInputs. The ABI is stable by design, but a version
        # bump warrants a quick sanity check before accepting.
        _libudevVersionCheck = assert pkgs.libudev-zero.version == "1.0.4"
          || builtins.throw ''
              libudev-zero version changed to ${pkgs.libudev-zero.version}.
              Verify ABI compatibility, then update the assertion in flake.nix.
            '';
          true;

        # ====================================================================
        # System dependencies
        # ====================================================================
        nativeBuildInputs =
          (with pkgs; [
            cmake
            clang
            pkg-config
            protobuf
          ])
          ++ pkgs.lib.optionals isLinux (with pkgs; [
            # lld and autoPatchelfHook are Linux-only: macOS uses ld64 and
            # does not have ELF RPATH patching.
            lld
            # autoPatchelfHook embeds Nix-store paths in RPATH so the binary
            # finds its .so deps without LD_LIBRARY_PATH. Production
            # deployment ships the binaries inside containers via
            # mkContainer, which bundles the full /nix/store closure;
            # /nix/store paths exist inside the image so RPATH resolves
            # cleanly.
            autoPatchelfHook
          ]);

        # Union of every C library any crate in the workspace might link.
        #
        # The deps phase (cargoArtifacts) needs this complete set: cargo
        # compiles every external crate including -sys crates whose build.rs
        # calls pkg-config for "their" library. Missing any one library
        # fails the deps phase even if no individual binary needs it.
        allBuildInputs =
          (with pkgs; [
            libudev-zero
          ])
          ++ pkgs.lib.optionals isLinux [
            pkgs.tpm2-tss.dev
            # Rust binaries implicitly depend on libgcc_s.so.1.
            # Putting it in buildInputs makes autoPatchelfHook find it and write
            # the correct /nix/store RPATH entry.
            pkgs.stdenv.cc.cc.lib
          ];

        # ====================================================================
        # Source filtering
        # ====================================================================

        # Declare sources additively using filesets. We start with crane's
        # defaults (Cargo.{toml,lock}, .rs files, rust-toolchain.toml) and add
        # extra non-Rust files referenced at build or test time. Being explicit
        # about what's included means changes outside these paths (helm charts,
        # READMEs, etc.) don't invalidate the Nix build cache.
        # The deps cache (cargoArtifacts) uses the narrower `depsSrc` below,
        # so .rs-only changes don't force an external-crate rebuild.

        # https://noogle.dev/f/lib/fileset/toSource/
        src = pkgs.lib.fileset.toSource {
          root = ./.; 
          # https://noogle.dev/f/lib/fileset/unions/
          fileset = pkgs.lib.fileset.unions [
            # https://crane.dev/API.html?highlight=commoncargoS#cranelibfilesetcommoncargosources
            (craneLib.fileset.commonCargoSources ./.)
            ./crates
            # Non-Rust files outside crates/ referenced at build/test time.
            ./.cargo
            # PXE boot templates referenced by crates via
            # include_str!("").
            ./pxe/templates
            ./pxe/ipxe/local
          ];
        };

        # Derive version from git. `self` refers to the flake itself
        version = self.shortRev or self.dirtyShortRev or "dev";

        # ====================================================================
        # Common arguments shared by all crane derivations.
        # ====================================================================
        commonArgs = {
          inherit
            src
            version
            nativeBuildInputs
            ;

          # Note: no buildInputs here. The deps phase and mkCrateBinary inject
          # `allBuildInputs` explicitly; individual binaries can append extra
          # inputs via extraArgs without affecting the shared dep-phase cache.
          pname = "carbide-workspace";
          strictDeps = true;
          doCheck = false;

          # Workspace-wide env vars.
          # The Nix sandbox has no network and no database. SQLX_OFFLINE tells
          # sqlx to use the pre-generated .sqlx/ query metadata checked into the
          # repo rather than connecting to a live Postgres instance at compile time.
          # Run `cargo sqlx prepare` against a real DB to regenerate .sqlx/ after
          # query changes, then commit the result.
          SQLX_OFFLINE = "true";
          PROTOC = "${pkgs.protobuf}/bin/protoc";
          PROTOC_INCLUDE = "${pkgs.protobuf}/include";
          # clang is already in nativeBuildInputs as the C compiler for -sys crates;
          # using it as the linker driver lets Cargo find lld (also in
          # nativeBuildInputs) without any additional path wiring.
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = "clang";

        };

        # ====================================================================
        # Phase 1: Build only workspace dependencies.
        #
        # This derivation compiles every external crate dependency but none
        # of the carbide source. Input hash depends only on Cargo.lock and
        # Cargo.toml files, so source-only changes get a cache hit here.
        # ====================================================================

        # https://crane.dev/API.html?highlight=cleanCargoSource#cranelibcleancargosource
        depsSrc = craneLib.cleanCargoSource ./.;

        # buildDepsOnly → mkCargoDerivation → stdenv.mkDerivation. Functions
        # that wrap mkDerivation accept `...` and forward unknown arguments
        # straight through, which is why passing `buildInputs` here works even
        # though buildDepsOnly doesn't explicitly declare that parameter.
        # https://crane.dev/API.html#cranelibbuilddepsonly
        # https://nixos.org/manual/nixpkgs/stable/#var-stdenv-buildInputs
        cargoArtifacts = craneLib.buildDepsOnly (
          commonArgs
          // {
            src = depsSrc;

            # Deps phase compiles every external -sys crate; needs the full
            # library union so each one's build.rs finds its C library via
            # pkg-config.
            buildInputs = allBuildInputs;
          }
        );


        # Builds one native workspace binary, reusing the pre-compiled external
        # crate cache from cargoArtifacts. See nix/rust/crate-binary.nix.
        mkCrateBinary = import ./nix/rust/crate-binary.nix {
          inherit
            craneLib
            commonArgs
            cargoArtifacts
            allBuildInputs
            ;
        };

        mkCrateHookLib = import ./nix/rust/crate-hook-lib.nix {
          inherit
            craneLib
            commonArgs
            cargoArtifacts
            allBuildInputs
            ;
        };

        # ====================================================================
        # Cross-compile pipeline for aarch64 binaries.
        #
        # Used for binaries that ship to aarch64 systems (carbide-scout,
        # carbide-agent, forge-dhcp-server, etc.). The helper intentionally
        # does not reuse native cargoArtifacts because x86_64 deps cannot be
        # reused for an aarch64 link; crane derives target-specific deps from
        # each cross package's args.
        # ====================================================================
        # pkgsCross.aarch64-multiplatform is a nixpkgs package set where every
        # derivation is built for aarch64-linux using a cross-compiler running
        # on the host. Overriding stdenv to gcc13Stdenv matches Ubuntu 24.04's
        # default toolchain and avoids ABI inconsistencies with the iPXE EFI
        # binary (also built with gcc 13 via ipxe-x86.nix).
        aarch64CrossPkgs = pkgs.pkgsCross.aarch64-multiplatform // {
          stdenv = pkgs.pkgsCross.aarch64-multiplatform.gcc13Stdenv;
        };

        mkCrossCrateBinary = import ./nix/rust/cross-crate-binary-aarch64.nix {
          inherit
            pkgs
            crane
            rustToolchainFor
            src
            version
            ;
          crossPkgs = aarch64CrossPkgs;
        };

        mkCrossHookLib = import ./nix/rust/cross-crate-hook-lib-aarch64.nix {
          inherit
            pkgs
            crane
            rustToolchainFor
            src
            version
            ;
          crossPkgs = aarch64CrossPkgs;
        };

        # libkea ships its C++ library as libkea-dhcp.so.* (versioned), but the
        # linker resolves -lkea-dhcp++ by name. postConfigure symlinks it into a
        # stable tmpdir so both native and cross builds find it at the same path.
        dhcpCrateExtraArgs = dhcpPkgs: {
          buildInputs = with dhcpPkgs; [
            stdenv.cc.cc.lib
            kea
            boost.dev
          ];
          postConfigure = ''
            mkdir -p $TMPDIR/kea-lib
            ln -sf ${dhcpPkgs.kea}/lib/libkea-*.so* $TMPDIR/kea-lib
            ln -sf ${dhcpPkgs.kea}/lib/libkea-dhcp.so $TMPDIR/kea-lib/libkea-dhcp++.so
            export KEA_LIB_PATH="$TMPDIR/kea-lib"
          '';
          KEA_INCLUDE_PATH = "${dhcpPkgs.kea}/include/kea";
          KEA_LIB_PATH = "${dhcpPkgs.kea}/lib";
        };

        # Shared metadata applied to every carbide workspace binary.
        # bombon reads meta.license and meta.homepage to populate
        # the licenseDeclared / downloadLocation fields in generated SBOMs.
        carbideMeta = {
          license = pkgs.lib.licenses.asl20;
          homepage = "https://github.com/NVIDIA/infra-controller";
          maintainers = [ ];
        };

        # ====================================================================
        # Per-architecture binary sets
        #
        # The cargo PACKAGE names are carbide-* but each crate's [[bin]] target
        # may rename the BINARY to forge-* — so we build by package name and
        # downstream consumers see the forge-* binary in $out/bin/.
        # ====================================================================

        nativeRustBinaries = {
          carbide-api = mkCrateBinary { pname = "carbide-api"; meta = carbideMeta; };
          carbide-dns = mkCrateBinary { pname = "carbide-dns"; meta = carbideMeta; };
          carbide-pxe = mkCrateBinary { pname = "carbide-pxe"; meta = carbideMeta; };
          carbide-dhcp = mkCrateHookLib {
            pname = "carbide-dhcp";
            libFileName = "libdhcp.so";
            installPath = "usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp.so";
            meta = carbideMeta;
            extraArgs = dhcpCrateExtraArgs pkgs;
          };
          carbide-dsx-exchange-consumer = mkCrateBinary { pname = "carbide-dsx-exchange-consumer"; meta = carbideMeta; };
          carbide-admin-cli = mkCrateBinary { pname = "carbide-admin-cli"; meta = carbideMeta; };
          carbide-health = mkCrateBinary { pname = "carbide-health"; meta = carbideMeta; };
          carbide-ssh-console = mkCrateBinary { pname = "carbide-ssh-console"; meta = carbideMeta; };
          # carbide-scout produces a binary named "forge-scout" (per the crate's
          # [[bin]] target); downstream packaging wraps it as needed.
          carbide-scout = mkCrateBinary { pname = "carbide-scout"; meta = carbideMeta; };
          carbide-log-parser = mkCrateBinary { pname = "carbide-log-parser"; meta = carbideMeta; };
          carbide-bmc-proxy = mkCrateBinary { pname = "carbide-bmc-proxy"; meta = carbideMeta; };
        };

        # DPU-side binaries. Build host can be either x86_64 or aarch64 —
        # pkgsCross.aarch64-multiplatform resolves to a real cross gcc on x86
        # hosts and to the native aarch64 gcc on aarch64 hosts.
        aarch64Binaries = {
          carbide-dpf = mkCrossCrateBinary {
            pname = "carbide-dpf";
            cargoExtraArgs = "--features driver --bin carbide-dpf-api-harness";
          };
          forge-dpu-agent = mkCrossCrateBinary { pname = "carbide-agent"; meta = carbideMeta; };
          forge-dhcp-server = mkCrossCrateBinary { pname = "carbide-dhcp-server"; meta = carbideMeta; };
          carbide-fmds = mkCrossCrateBinary { pname = "carbide-fmds"; meta = carbideMeta; };
        };

        # Server-side binaries cross-compiled for aarch64. Used alongside
        # aarch64Binaries to build arm64 service containers from an x86_64 host.
        aarch64ServerBinaries =
          let
            mk = pname: mkCrossCrateBinary { inherit pname; };
          in
          {
            carbide-api = mk "carbide-api";
            carbide-dns = mk "carbide-dns";
            carbide-pxe = mk "carbide-pxe";
            carbide-dhcp = mkCrossHookLib {
              pname = "carbide-dhcp";
              libFileName = "libdhcp.so";
              installPath = "usr/lib/aarch64-linux-gnu/kea/hooks/libdhcp.so";
              extraArgs = dhcpCrateExtraArgs aarch64CrossPkgs;
            };
            carbide-dsx-exchange-consumer = mk "carbide-dsx-exchange-consumer";
            carbide-admin-cli = mk "carbide-admin-cli";
            carbide-health = mk "carbide-health";
            carbide-ssh-console = mk "carbide-ssh-console";
            carbide-scout = mk "carbide-scout";
          };

        # passthruVendoredSbom attaches cargo-cyclonedx SBOM data to each binary
        # derivation's passthru so buildBom can merge Rust crate license metadata
        # with nixpkgs metadata for the full closure. buildBom alone only sees
        # what nixpkgs knows — not the crate-level licenses from Cargo.toml.
        nativeRustBinariesWithSbom = pkgs.lib.mapAttrs (
          _name: pkg:
            bombon.lib.${system}.passthruVendoredSbom.rust pkg { inherit pkgs; }
        ) nativeRustBinaries;

        rustSboms = pkgs.lib.mapAttrs' (
          name: pkg: pkgs.lib.nameValuePair "${name}-sbom"
            (bombon.lib.${system}.buildBom pkg { includeBuildtimeDependencies = false; })
        ) nativeRustBinariesWithSbom;

        # Container SBOMs: one per service image, covering both the carbide
        # binary (license from cargo metadata via passthruVendoredSbom) and
        # every runtime package in the container closure (license from nixpkgs
        # metadata).
        #
        # buildBom is called on the Rust binary (sbomPackages[0]) with the
        # runtime deps as extraPaths — same pattern as the in-container
        # attribution file. See the attributionSbom comment in mkContainer.
        containerSboms = pkgs.lib.mapAttrs' (
          name: container:
          let
            pkgs_ = container.passthru.sbomPackages;
            rt = container.passthru.sbomRuntime;
          in
          pkgs.lib.nameValuePair "${name}-sbom"
            (bombon.lib.${system}.buildBom (builtins.head pkgs_) {
              includeBuildtimeDependencies = false;
              extraPaths = pkgs.lib.tail pkgs_ ++ rt ++ [ pkgs.cacert ];
            })
        ) containers;

        # ====================================================================
        # Go binaries (rest-api workspace)
        # ====================================================================

        # Vendor hash for the rest-api Go module. TOFU on first build:
        #   1. Set to `pkgs.lib.fakeHash` (already so below).
        #   2. Run `nix build .#rest-api-api` — the build fails at vendoring
        #      with a "hash mismatch" error printing the expected sha256.
        #   3. Copy that sha256 here and rebuild.
        #   4. Any updates to go.mod will require an updated hash
        #      This is one of the guarantees of nix's hermetics.  One is 
        #      fixed output derivations. Nix fetches this before the build
        #      verifies the hash, and only then makes it availble for your build.
        # All rest-api binaries share this — they all live under the same
        # go.mod, so vendoring is identical for each.
        restApiVendorHash = "sha256-Dx8K84zFnDSHs8o82a7IHcPOdePQfJAHNuxt8aXnntE=";

        restApi = import ./nix/go/rest-api.nix {
          inherit pkgs version system;
          src = ./rest-api;
          vendorHash = restApiVendorHash;
        };
        restApiBinariesFor = restApi.binariesFor;
        restApiBinariesNative = restApi.binariesNative;
        restApiBinariesAmd64 = restApi.binariesAmd64;
        restApiBinariesArm64 = restApi.binariesArm64;

        # CLI tools exposed by `nix develop`. Container runtime tools are
        # selected separately in `serviceRuntime` so each image only carries
        # the shell-out utilities it actually needs.
        runtimeTools = with pkgs; [
          curl
          ipmitool
          iproute2
          iputils # ping, traceroute, arping
          kea # kea-dhcp4-server + kea-ctrl-agent
          openipmi
          postgresql_15 # psql, pg_dump, etc.
          tpm2-tools
        ];

        # ====================================================================
        # Container builder — see nix/container/make-container.nix for the
        # two-phase build, SBOM strategy, and parameter documentation.
        # ====================================================================

        mkOssSources = import ./nix/container/oss-sources.nix { inherit pkgs; };

        mkContainer = import ./nix/container/make-container.nix {
          inherit
            pkgs
            nix2containerLib
            containerCopyHelpers
            bombon
            system
            version
            mkOssSources
            ;
        };

        # Build a self-contained Debian package from a Nix derivation.
        # Bundles the full /nix/store closure inside the deb so the binary
        # runs on bare-metal Ubuntu Noble hosts without a Nix installation.
        # See nix/deb/make-deb.nix for full documentation.
        mkDebPackage = import ./nix/deb/make-deb.nix { inherit pkgs version; };

        # Pre-built third-party aarch64 binaries — fetched as fixed-output
        # derivations so Nix can verify them without network access at build time.
        mftAarch64 = import ./nix/third-party/mft-aarch64.nix {
          inherit pkgs;
          crossPkgs = aarch64CrossPkgs;
        };

        transceiverExporterAarch64 = import ./nix/third-party/transceiver-exporter-aarch64.nix {
          inherit pkgs;
          crossPkgs = aarch64CrossPkgs;
        };

        otelcolContribAarch64 = import ./nix/container/otelcol-contrib-aarch64.nix {
          inherit pkgs;
          crossPkgs = aarch64CrossPkgs;
        };

        # Scripts and firmware bundled into the nsm container at the paths the
        # Dockerfile establishes (WORKDIR /opt/nvswitch-manager before COPY).
        nsmStaticFiles = pkgs.runCommand "rest-api-nsm-static" { } ''
          mkdir -p $out/opt/nvswitch-manager
          cp -r ${./rest-api/nvswitch-manager/scripts}  $out/opt/nvswitch-manager/scripts
          cp -r ${./rest-api/nvswitch-manager/firmware} $out/opt/nvswitch-manager/firmware
        '';

        # mkServiceRuntime takes a package set so the same map works for both
        # amd64 (pkgs) and arm64 (aarch64CrossPkgs) container builds.
        mkServiceRuntime = p: {
          carbide-dns = with p; [ busybox ];
          carbide-pxe = with p; [ busybox ];
          carbide-dhcp = with p; [ kea busybox ];
          carbide-api = with p; [ tpm2-tools ipmitool busybox iputils iproute2 ];
          forge-dpu-agent = [ mftAarch64 ] ++ (with p; [ bash python3 iproute2 lldpd cri-tools busybox ]);
          carbide-fmds = with p; [ busybox ];
          forge-dhcp-server = with p; [ kea busybox ];
          otelcol-contrib  = [ otelcolContribAarch64.passthru.wrapperScripts ] ++ (with p; [ bash busybox ]);
          rest-api-nsm     = [ nsmStaticFiles ];
        };

        # Shell commands run at image build time to pre-create directories that
        # services expect to exist at startup.
        serviceExtraCommands = {
          carbide-dhcp = "mkdir -p var/run/kea";
          forge-dhcp-server = ''
            mkdir -p var/run/kea
            mkdir -p var/support/forge-dhcp/bin
            ln -sf /bin/forge-dhcp-server var/support/forge-dhcp/bin/forge-dhcp-server
          '';
        };

        # Legacy /opt/carbide/<alias> → /bin/<target> symlinks per service.
        # Needed while PodSpecs still reference pre-rename binary names.
        serviceOptCarbideAliases = {
          carbide-admin-cli = [
            { alias = "forge-admin-cli";   target = "nico-admin-cli"; }
            { alias = "carbide-admin-cli"; target = "nico-admin-cli"; }
          ];
        };

        # OCI Entrypoint per service. Only set for containers that run standalone
        # (DPU images, sidecars) where the image itself must declare what to run.
        # Server-side containers leave this unset — k8s PodSpecs drive execution.
        serviceEntrypoints = {
          carbide-fmds = [ "/bin/carbide-fmds" ];
          forge-dpu-agent = [ "/bin/forge-dpu-agent" ];
          forge-dhcp-server = [ "/var/support/forge-dhcp/bin/forge-dhcp-server" ];
          transceiver-exporter = [ "/usr/bin/transceiver-exporter" ];
          otelcol-contrib      = [ "/etc/otelcol-contrib/otelcol-wrapper" ];
        };

        # Legacy /opt/carbide/ directory stubs per service.
        # Empty directories that services or k8s init containers may expect
        # to exist at startup (mount points, runtime path checks, etc.).
        serviceOptCarbideDirs = {
          carbide-api = [ "pxe/templates" "migrations" "static" "firmware" ];
        };

        # Per-service containers — one image per binary per architecture.
        #
        # amd64 containers use nativeRustBinariesWithSbom (bombon SBOM passthru)
        # and native pkgs runtime tools.
        # arm64 containers use aarch64ServerBinaries / aarch64Binaries (cross-
        # compiled) and aarch64CrossPkgs runtime tools.
        #
        # Exposed at:
        #   nix build .#carbide-api-container          # amd64
        #   nix build .#carbide-api-container-arm64    # arm64
        containers =
          let
            mkServiceContainer =
              name: pkg: p:
              mkContainer {
                inherit name;
                packages = [ pkg ];
                runtime = (mkServiceRuntime p).${name} or [ ];
                extraCommands = serviceExtraCommands.${name} or "";
                optCarbideAliases = serviceOptCarbideAliases.${name} or [ ];
                optCarbideDirs = serviceOptCarbideDirs.${name} or [ ];
                entrypoint = serviceEntrypoints.${name} or null;
                meta = carbideMeta;
              };

            # amd64 — native binaries with SBOM passthru + native runtime.
            nativeServices = nativeRustBinariesWithSbom // restApiBinariesNative;
            amd64Containers = pkgs.lib.mapAttrs' (
              name: pkg:
              pkgs.lib.nameValuePair "${name}-container" (mkServiceContainer name pkg pkgs)
            ) nativeServices;

            # arm64 — cross-compiled server binaries + cross runtime packages.
            # DPU-specific binaries (forge-dpu-agent, carbide-fmds, forge-dhcp-server)
            # already live in aarch64Binaries; server binaries are in aarch64ServerBinaries.
            aarch64Services = aarch64ServerBinaries // {
              inherit (aarch64Binaries) forge-dpu-agent carbide-fmds forge-dhcp-server;
              transceiver-exporter = transceiverExporterAarch64;
              otelcol-contrib      = otelcolContribAarch64;
            } // restApiBinariesFor "arm64";
            arm64Containers = pkgs.lib.mapAttrs' (
              name: pkg:
              pkgs.lib.nameValuePair "${name}-container-arm64"
                (mkServiceContainer name pkg aarch64CrossPkgs)
            ) aarch64Services;

          in
          amd64Containers // arm64Containers;

        # ====================================================================
        # Deb packages — binaries that run directly on bare-metal Ubuntu Noble
        # hosts where containers are not an option (e.g. the scout initramfs).
        # ====================================================================
        debs = import ./nix/deb/debs.nix {
          inherit pkgs mkDebPackage nativeRustBinaries;
          carbideScoutAarch64 = carbide-scout-aarch64;
          forgeScoutServiceFile = ./crates/scout/misc/forge-scout.service;
          forgeScoutPostinst = ./crates/scout/misc/DEBIAN/postinst;
        };

        # ====================================================================
        # iPXE EFI bootloader for x86_64.
        #
        # When upstream iPXE is bumped, update both ipxeRev and ipxeHash.
        # First build with a new rev fails with a hash mismatch — copy
        # the reported hash into ipxeHash and rebuild.
        # ====================================================================
        # Shared inputs for both iPXE arches (commit pin and config headers).
        # Each arch picks its own patch set based on what it actually needs.
        ipxeRev = "bbd7821bd42da5456ee068a471ef73d525ea26a1";
        ipxeHash = "sha256-5jzKYvIPkOP1Z7t7OsvmAaY0BI7g793jTh8MfrPpfP8=";
        ipxeConfigHeaders = [
          ./pxe/ipxe/local/branding.h
          ./pxe/ipxe/local/general.h
          ./pxe/ipxe/local/settings.h
        ];

        ipxe-efi-x86 = import ./nix/boot/ipxe-x86.nix {
          inherit
            pkgs
            ipxeRev
            ipxeHash
            ipxeConfigHeaders
            ;
          ipxePatches = [
            ./pxe/ipxe/local/0001-efi-Add-TPM-measurement-API-via-TCG-v1-and-TCG-v2-EF.patch
	    ./pxe/ipxe/local/0001-fix-update-to-allow-iPXE-to-boot-on-BlueField-NICs.patch
            ./pxe/ipxe/local/0003-efi-prevent-load-image-watchdog-timeout.patch
          ];
          bannerVersion = "carbide-${version}";
          # Without EMBED= the EFI image runs only iPXE's built-in per-NIC
          # autoboot and falls through to "Nothing to boot" — no boot script
          # means no carbide DHCP next-server/filename handoff.
          embedScript = ./pxe/ipxe/local/embed.ipxe;
        };

        # ====================================================================
        # iPXE EFI bootloader for aarch64.
        #
        # Cross-compiled from x86_64 build hosts using
        # pkgsCross.aarch64-multiplatform.gcc13Stdenv. Shares the same patch
        # set as the x86 build: TPM measurement, BlueField NIC boot, and the
        # EFI watchdog fix.
        # ====================================================================
        ipxe-efi-aarch64 = import ./nix/boot/ipxe-aarch64.nix {
          inherit
            pkgs
            ipxeRev
            ipxeHash
            ipxeConfigHeaders
            ;
          ipxePatches = [
            ./pxe/ipxe/local/0001-efi-Add-TPM-measurement-API-via-TCG-v1-and-TCG-v2-EF.patch
	    ./pxe/ipxe/local/0001-fix-update-to-allow-iPXE-to-boot-on-BlueField-NICs.patch
            ./pxe/ipxe/local/0003-efi-prevent-load-image-watchdog-timeout.patch
          ];
          bannerVersion = "carbide-${version}";
          embedScript = ./pxe/ipxe/local/embed.ipxe;
        };

        # carbide-scout cross-compiled for aarch64. Consumed by the
        # forge-scout-deb-arm64 deb package defined in nix/deb/debs.nix.
        carbide-scout-aarch64 = mkCrossCrateBinary { pname = "carbide-scout"; };
      in
      {
        # ==================================================================
        # Packages — `nix build .#<name>`
        # ==================================================================

        packages =
          if system == "x86_64-linux" then
            # x86 server-side binaries (native) + aarch64 DPU/server binaries
            # (cross-compiled) + rest-api Go binaries (both arches via
            # GOARCH) merged into one attribute set. No name overlap — every
            # binary has a unique attribute name. From an x86 dev machine,
            # `nix build .#forge-dpu-agent` cross-compiles to aarch64;
            # `nix build .#rest-api-api-aarch64` cross-compiles Go to arm64.
            nativeRustBinaries
            // aarch64Binaries
            // restApiBinariesAmd64
            // restApiBinariesArm64
            // containers
            // debs
            // rustSboms
            // containerSboms
            // {
              inherit
                ipxe-efi-x86
                ipxe-efi-aarch64
                carbide-scout-aarch64
                ;

              # Expose the deps-only derivation so CI can cache it directly.
              # `nix build .#deps` builds just the dep phase — useful for
              # warming the binary cache after Cargo.lock changes.
              deps = cargoArtifacts;
            }
          else if system == "aarch64-linux" then
            # Native aarch64 build host. nativeRustBinaries/aarch64Binaries both
            # evaluate against aarch64 `pkgs` here, producing aarch64
            # binaries; the cross-compile path (mkCrossCrateBinary) becomes
            # a no-op cross since target = host. rest-api Go binaries:
            # amd64 set still needs cross (GOARCH=amd64 from aarch64 host).
            nativeRustBinaries
            // aarch64Binaries
            // restApiBinariesAmd64
            // restApiBinariesArm64
            // containers
            // rustSboms
            // containerSboms
            // {
              inherit
                ipxe-efi-aarch64
                ;
            }
          else
            { };

        # Container copy-to-Docker apps are Linux-only: nix2container's skopeo
        # nix: transport is not available on Darwin.
        # Multi-arch manifest creation is handled in CI via crane/skopeo directly.
        apps = pkgs.lib.optionalAttrs isLinux (
          # `nix run .#<name>-container-copy-to-docker` loads the amd64 image
          # into the local Docker daemon via the patched skopeo nix: transport.
          pkgs.lib.mapAttrs' (
            name: container:
            pkgs.lib.nameValuePair "${name}-copy-to-docker" {
              type = "app";
              program = "${container.passthru.copyToDockerDaemon}/bin/copy-to-docker-daemon";
            }
          ) (pkgs.lib.filterAttrs (n: _: !(pkgs.lib.hasSuffix "-arm64" n)) containers)
        );

        # ==================================================================
        # Dev shell — `nix develop`
        # ==================================================================

        devShells.default = craneLib.devShell (
          {
            packages =
              (with pkgs; [
                cargo-make
                cargo-nextest
                sccache
                sqlx-cli
                taplo
                # Go toolchain matches rest-api/go.mod's `go 1.25.4`. Plus
                # gopls / delve for editor LSP and debugging.
                go_1_25
                gopls
                delve
              ])
              # Runtime tools (kea, ipmitool, tpm2-tools, etc.) are Linux-only.
              ++ pkgs.lib.optionals isLinux runtimeTools;

            # Dev shell needs the full library set so contributors can build
            # any crate via `cargo build`, not just one specific binary.
            # tpm2-tss and other Linux-only libs are excluded on Darwin via
            # allBuildInputs already being gated.
            buildInputs = allBuildInputs;
            inherit nativeBuildInputs;

            # Route cargo compilations through sccache. First run populates
            # the cache at ~/.cache/sccache; subsequent builds of the same
            # source (across branches, checkouts, rebuilds) get cache hits
            # at the individual object file level.
            RUSTC_WRAPPER = "sccache";

            SQLX_OFFLINE = "true";
            PROTOC = "${pkgs.protobuf}/bin/protoc";
            PROTOC_INCLUDE = "${pkgs.protobuf}/include";
          }
          // pkgs.lib.optionalAttrs isLinux {
            KEA_INCLUDE_PATH = "${pkgs.kea}/include/kea";
            KEA_LIB_PATH = "${pkgs.kea}/lib";

            # Ensure dev-shell aarch64 cross-builds use the same 64KB-page-
            # compatible max-page-size as `nix build`. ARM64 server hardware
            # (NVIDIA Grace, certain Ampere SKUs) runs 64KB-page kernels;
            # binaries linked with the default 4KB segment alignment can
            # load incorrectly there. Target-suffixed env var → no effect
            # on native x86 builds.
            CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS = "-C link-arg=-Wl,-z,max-page-size=0x10000";
          }
        );
      }
    );
}

