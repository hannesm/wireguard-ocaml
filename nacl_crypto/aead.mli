open Core
open Key

val encrypt
  :  key:secret key
  -> counter:int64
  -> message:Bytes.t
  -> auth_text:Bytes.t
  -> Bytes.t Or_error.t

val decrypt
  :  key:secret key
  -> counter:int64
  -> ciphertext:Bytes.t
  -> auth_text:Bytes.t
  -> Bytes.t Or_error.t
