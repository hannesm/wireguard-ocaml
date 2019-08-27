open Core
open Key

val xaead_encrypt :
     key:shared_key
  -> nonce:Bytes.t
  -> message:Bytes.t
  -> auth_text:Bytes.t
  -> Bytes.t Or_error.t

val xaead_decrypt :
     key:shared_key
  -> nonce:Bytes.t
  -> ciphertext:Bytes.t
  -> auth_text:Bytes.t
  -> Bytes.t Or_error.t
