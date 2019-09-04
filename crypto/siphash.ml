open Core

external siphash_ : bytes -> bytes -> int -> bytes -> int
  = "caml_crypto_siphash"

let hash_bytes_out = 8

(* CR crichoux: test me *)
let siphash ~key ~input =
  let out_buf = Bytes.create hash_bytes_out in
  let status = siphash_ out_buf input (Bytes.length input) key in
  if status < 0 then
    Or_error.error_s [%message "failed to hash" (status : int)]
  else Or_error.return out_buf
