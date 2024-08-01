{
  description = "Rust flake";
  inputs =
    {
      nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable"; # or whatever vers
    };
  
  outputs = { self, nixpkgs, ... }@inputs:
    let
     system = "aarch64-darwin"; # your version
     pkgs = nixpkgs.legacyPackages.${system};    
    in
    {
      devShells.${system}.default = pkgs.mkShell
      {
        packages = with pkgs; [ rustup cargo ]; # whatever you need
      };
    };
}