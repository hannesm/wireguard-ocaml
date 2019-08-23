open! Core

type 'a key = Bytes.t [@@deriving sexp_of]

type shared [@@deriving sexp_of]

type secret [@@deriving sexp_of]

type public [@@deriving sexp_of]

type keypair = {secret: secret key; public: public key} [@@deriving sexp_of]

external random_buffer_ : Bytes.t -> int -> unit = "caml_crypto_gen_key"

let random_buffer len =
  let buf = Bytes.make len '\x00' in
  random_buffer_ buf len ; buf
