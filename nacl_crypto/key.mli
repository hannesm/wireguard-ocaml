type 'a key = Bytes.t [@@deriving sexp_of]
type secret [@@deriving sexp_of]
type public [@@deriving sexp_of]
type shared [@@deriving sexp_of]

type keypair =
  { secret : secret key
  ; public : public key
  }
[@@deriving sexp_of]

val random_buffer : int -> bytes
