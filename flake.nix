{
  description = "A basic devshell for us";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = {
    self,
    nixpkgs,
  }: let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};

    python = pkgs.python312;
    pythonPackages = with python.pkgs; [
      # image manipulation
      wand

      # math stuff for crypto challenges.
      # Note that certain things simply require SageMath,
      # which is only packaged as its own venv, and has to be accessed via
      # the wrapped `sage` cli for now.
      pycryptodome
      numpy
      sympy

      # socket shenanigans
      pwntools
    ];
  in {
    devShells.x86_64-linux.default = pkgs.mkShell {
      packages =
        [
          pkgs.deno
          pkgs.basedpyright

          # cli tools for steg/forensics
          pkgs.exiftool
          pkgs.binwalk
          pkgs.imagemagick

          # netcat, telnet, etc
          pkgs.inetutils
          pkgs.socat

          # reversing
          pkgs.jadx # android
          pkgs.ghidra # x86_64 executables

          # cli tools for crypto / math
          pkgs.sage

          python
        ]
        ++ pythonPackages;
    };
  };
}
