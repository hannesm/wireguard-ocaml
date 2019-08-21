(lang dune 1.11)
(name wireguard-ocaml)

(generate_opam_files true)

(license MIT)

(maintainers "laudecay <laudecay@gmail.com>")
(authors "laudecay <laudecay@gmail.com>")

(source (github laudecay/wireguard-ocaml))

(package
  (name wireguard-ocaml)
  (depends digestif core ctypes hex ocplib-endian ppx_inline_test)
  (synopsis "Wireguard, but this time it's in ocaml")
)
