open! Core

type shared_key = bytes [@@deriving sexp_of]

type secret_key = bytes [@@deriving sexp_of]

type public_key = bytes [@@deriving sexp_of]

type keypair = {secret: secret_key; public: public_key} [@@deriving sexp_of]

let shared_to_bytes bytes = bytes
let shared_of_bytes bytes = bytes
let secret_to_bytes bytes = bytes
let secret_of_bytes bytes = bytes

external random_buffer_ : Bytes.t -> int -> unit = "caml_crypto_gen_key"

let random_buffer len =
  let buf = Bytes.make len '\x00' in
  random_buffer_ buf len ; buf
