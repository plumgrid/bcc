{ pkgs ? import <nixpkgs> {} }:
with pkgs;
let
  inherit (linux) stdenv; # in particular, use the same compiler by default
  inherit (pkgs) fetchFromGitHub fetchpatch makeWrapper cmake llvmPackages
    flex bison elfutils python pythonPackages luajit netperf iperf libelf;
  inherit (pkgs.linuxPackages) systemtap;
  kernel = linux;
in
  stdenv.mkDerivation rec {
    version = "0.5.0";
    name = "bcc-${version}";

    buildInputs =  [
      llvmPackages.llvm llvmPackages.clang-unwrapped kernel
      elfutils python pythonPackages.netaddr luajit netperf iperf
      systemtap.stapBuild
    ];

    nativeBuildInputs =  [ makeWrapper cmake flex bison ]
      # libelf is incompatible with elfutils-libelf
      ++ stdenv.lib.filter (x: x != libelf) kernel.moduleBuildDependencies;

    cmakeFlags =
      [ "-DBCC_KERNEL_MODULES_DIR=${kernel.dev}/lib/modules"
      "-DREVISION=${version}"
      "-DENABLE_USDT=ON"
      "-DENABLE_CPP_API=ON"
    ];

    dontFixCmake = true;

    shellHook = ''
      cmakeConfigurePhase 2>&1 > /dev/null
      export LD_LIBRARY_PATH="$PWD/build/src/cc:$LD_LIBRARY_PATH"
      export PYTHONPATH="$PWD/src/python:$PYTHONPATH"
    '';
  }
