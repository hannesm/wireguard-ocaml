open! Core

type shared_key = bytes [@@deriving sexp_of]

type secret_key = bytes [@@deriving sexp_of]

type public_key = bytes [@@deriving sexp_of]

type keypair = {secret: secret_key; public: public_key} [@@deriving sexp_of]

let constant_time_byte_eq (x:char) (y:char) : int =
    let x, y = int_of_char x, int_of_char y in
    let z = ref (lnot (x lxor y)) in
    z := !z land (!z lsr 4);
    z := !z land (!z lsr 2);
    z := !z land (!z lsr 1);
    !z
;;

let is_zero bytes : bool =
  let acc = ref 1 in
  for i = 0 to Bytes.length bytes do
    acc := !acc
      land (constant_time_byte_eq (Bytes.get bytes i) '\x00')
  done;
  !acc = 1
;;

let set_zero bytes : unit =
  Bytes.fill ~pos:0 ~len:(Bytes.length bytes) bytes '\x00'
;;

let shared_to_bytes bytes = bytes
let shared_of_bytes bytes = bytes
let secret_to_bytes bytes = bytes
let secret_of_bytes bytes = bytes

external random_buffer_ : Bytes.t -> int -> unit = "caml_crypto_gen_key"

let random_buffer len =
  let buf = Bytes.make len '\x00' in
  random_buffer_ buf len ; buf
