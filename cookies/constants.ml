open Core
open Or_error.Let_syntax

(* CR crichoux: don't expose this *)
(* CR crichoux: add finalizers *)

let wg_label_mac1 = Bytes.of_string "mac1----"
let wg_label_cookie = Bytes.of_string "cookie--"
let mac_size = 32
let cookie_refresh_time = Time_ns.Span.of_sec 120.

let init_constants pk : (bytes * bytes * bytes) Or_error.t =
  let pk_bytes = Crypto.Public.to_bytes pk in
  Gc.full_major () ;
  print_string "mac1 label bytes" ;
  Cstruct.of_bytes wg_label_mac1 |> Cstruct.hexdump ;
  print_string "pk bytes" ;
  Cstruct.of_bytes pk_bytes |> Cstruct.hexdump ;
  let%bind mac1_key = Crypto.hash2 wg_label_mac1 pk_bytes in
  let%map mac2_encryption_key = Crypto.hash2 wg_label_cookie pk_bytes in
  let time = Tai64n.now () |> Tai64n.to_bytes in
  (mac1_key, mac2_encryption_key, time)
