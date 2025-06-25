{
  description = "AES_CPP";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux"; # ou "aarch64-linux" selon ta machine
      pkgs = import nixpkgs { inherit system; };
    in {
      packages.${system}.default = pkgs.stdenv.mkDerivation {
        pname = "aes_cpp";
        version = "1.0";
        src = ./.;

        nativeBuildInputs = [ pkgs.cmake ];
        buildInputs = [ pkgs.boost pkgs.gcc pkgs.qt6.full];

        cmakeFlags = [
          "-DCMAKE_BUILD_TYPE=Release"
          "-DENABLE_TESTS=OFF"
          "-DCMAKE_PREFIX_PATH=${pkgs.boost}"
        ];

        installPhase = ''
          mkdir -p $out/bin
          cp aes_cpp_ui/aes_cpp_ui $out/bin/
          cp AES_CPP $out/bin/
        '';
      };

    };
}
