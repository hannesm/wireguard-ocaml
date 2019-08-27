type secret_key [@@deriving sexp_of]

type public_key = bytes [@@deriving sexp_of]

type shared_key [@@deriving sexp_of]

type keypair = {secret: secret_key; public: public_key} [@@deriving sexp_of]

(* CR crichoux: hide these from outer world! *)
val shared_to_bytes : shared_key -> bytes
val shared_of_bytes : bytes -> shared_key
val secret_to_bytes : secret_key -> bytes
val secret_of_bytes : bytes -> secret_key

val random_buffer : int -> bytes
val is_zero : bytes -> bool
val set_zero : bytes  -> unit
