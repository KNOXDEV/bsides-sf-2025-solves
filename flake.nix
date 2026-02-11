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

    # You'll notice that we register our python packages separately from the interpreter
    # as opposed to using the more typical `python.withPackages` to create an environment.
    # This is equivilent to installing them "globally" (although still within the temporary shell).
    python = pkgs.python313;
    pythonPackages = with python.pkgs; [
      # image manipulation
      wand

      # math stuff for crypto challenges.
      pycryptodome
      numpy
      sympy
      # Including sage.lib in my inputs lets me use (most) Sage functionality in Python files.
      # Also note that this is not pinned to the above selected interpreter.
      # https://github.com/NixOS/nixpkgs/blob/master/pkgs/by-name/sa/sage/sage.nix
      pkgs.sage.lib

      # socket shenanigans
      pwntools
    ];
  in {
    devShells.x86_64-linux.default = pkgs.mkShell {
      packages =
        [
          pkgs.deno

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
