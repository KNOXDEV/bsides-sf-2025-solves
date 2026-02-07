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
      pycryptodome
      wand
      numpy
    ];
  in {
    devShells.x86_64-linux.default = pkgs.mkShell {
      packages = [
        pkgs.deno
        pkgs.basedpyright

        # cli tools for steg/forensics
        pkgs.exiftool
        pkgs.binwalk
        pkgs.imagemagick

        # java
        pkgs.jadx

        python
      ] ++ pythonPackages;


    };
  };
}
