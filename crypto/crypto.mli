val init : unit -> unit Core.Or_error.t

type secret_key = Key.secret_key [@@deriving sexp_of]
type public_key = bytes [@@deriving sexp_of]
type shared_key = Key.shared_key [@@deriving sexp_of]
type keypair = Key.keypair = { secret : secret_key; public : public_key; } [@@deriving sexp_of]

val shared_of_bytes : bytes -> shared_key
val shared_to_bytes : shared_key -> bytes

val secret_of_bytes : bytes -> secret_key

val random_buffer : int -> public_key
val is_zero : public_key -> bool
val set_zero : public_key -> unit

val aead_encrypt :
  key:Key.shared_key ->
  counter:int64 -> message:bytes -> auth_text:bytes -> bytes Core.Or_error.t
val aead_decrypt :
  key:Key.shared_key ->
  counter:int64 ->
  ciphertext:bytes -> auth_text:bytes -> bytes Core.Or_error.t

val generate : unit -> Key.keypair Core.Or_error.t
val dh :
  public:bytes -> secret:Key.secret_key -> Key.shared_key Core.Or_error.t

val kdf_1 : key:Key.shared_key -> bytes -> Key.shared_key
val kdf_2 : key:Key.shared_key -> bytes -> Key.shared_key * Key.shared_key
val kdf_3 :
  key:Key.shared_key ->
  bytes -> Key.shared_key * Key.shared_key * Key.shared_key

val hash : bytes -> bytes Core.Or_error.t
val hash2 : bytes -> bytes -> bytes Core.Or_error.t
val mac : input:bytes -> key:Key.shared_key -> bytes Core.Or_error.t
val hmac : input:bytes -> key:Key.shared_key -> bytes

val xaead_encrypt :
  key:Key.shared_key ->
  nonce:bytes -> message:bytes -> auth_text:bytes -> bytes Core.Or_error.t
val xaead_decrypt :
  key:Key.shared_key ->
  nonce:bytes -> ciphertext:bytes -> auth_text:bytes -> bytes Core.Or_error.t
