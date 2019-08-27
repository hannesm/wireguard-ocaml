open Core
open Key

val aead_encrypt :
     key:shared_key
  -> counter:int64
  -> message:Bytes.t
  -> auth_text:Bytes.t
  -> Bytes.t Or_error.t

val aead_decrypt :
     key:shared_key
  -> counter:int64
  -> ciphertext:Bytes.t
  -> auth_text:Bytes.t
  -> Bytes.t Or_error.t
