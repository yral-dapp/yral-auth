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
        packages = with pkgs; [ rustup cargo cargo-leptos ]++ (if pkgs.stdenv.isDarwin then [
            darwin.apple_sdk.frameworks.Foundation
            pkgs.darwin.libiconv
            tailwindcss
            git
          ] else []);
          shellHook = ''
            if [ -d "/opt/homebrew/opt/llvm" ]; then
              export LLVM_PATH="/opt/homebrew/opt/llvm"
            else
              export LLVM_PATH="$(which llvm)"
            fi
            export RUSTC_WRAPPER=""
            export CC_wasm32_unknown_unknown=$LLVM_PATH/bin/clang
            export CXX_wasm32_unknown_unknown=$LLVM_PATH/bin/clang++
            export AS_wasm32_unknown_unknown=$LLVM_PATH/bin/llvm-as
            export AR_wasm32_unknown_unknown=$LLVM_PATH/bin/llvm-ar
            export STRIP_wasm32_unknown_unknown=$LLVM_PATH/bin/llvm-strip
          '';
      };
    };
}