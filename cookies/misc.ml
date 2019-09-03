open Core
open Or_error.Let_syntax

let wg_label_mac1 = Bytes.of_string "mac1----"
let wg_label_cookie = Bytes.of_string "cookie--"
let mac_size = 32
let cookie_refresh_time = Time_ns.Span.of_sec 120.

let make_nice_blit func t bytes =
  let cs = Cstruct.of_bytes bytes in
  func cs 0 t

let init_constants pk : (bytes * bytes * bytes) Or_error.t =
  let pk_bytes = Crypto.Public.to_bytes pk in
  let%bind mac1_key = Crypto.hash2 wg_label_mac1 pk_bytes in
  let%map mac2_encryption_key = Crypto.hash2 wg_label_cookie pk_bytes in
  let time = Tai64n.now () |> Tai64n.to_bytes in
  (mac1_key, mac2_encryption_key, time)

let get_macs msg : (Cstruct.t * Cstruct.t) * (Cstruct.t * Cstruct.t) =
  let size = Cstruct.len msg in
  let msg_alpha, mac1 =
    let msg_alpha, macs = Cstruct.split msg (size - (2 * mac_size)) in
    (msg_alpha, Cstruct.sub macs 0 mac_size) in
  let msg_beta, mac2 = Cstruct.split msg (size - mac_size) in
  ((msg_alpha, mac1), (msg_beta, mac2))

(* CR crichoux: write tests for set_mac1 *)
let set_mac1 ~msg ~mac1 : unit =
  let size = Cstruct.len msg in
  let mac1 = Cstruct.of_bytes mac1 in
  Cstruct.blit mac1 0 msg (size - (2 * mac_size)) mac_size

(* CR crichoux: write tests for set_mac2 *)
let set_mac2 ~msg ~mac2 : unit =
  let size = Cstruct.len msg in
  let mac2 = Cstruct.of_bytes mac2 in
  Cstruct.blit mac2 0 msg (size - mac_size) mac_size

let%expect_test "test get_macs" =
  Crypto.init () |> Or_error.ok_exn ;
  let mac1 =
    Cstruct.of_hex
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f" in
  let mac2 =
    Cstruct.of_hex
      "0f0e0d0c0b0a090807060504030201000f0e0d0c0b0a09080706050403020100" in
  let msg_hs_init = Noise.Message.new_handshake_initiation () in
  Noise.Message.blit_handshake_initiation_mac1 msg_hs_init
    (Cstruct.to_bytes mac1) ;
  Noise.Message.blit_handshake_initiation_mac2 msg_hs_init
    (Cstruct.to_bytes mac2) ;
  let (msg_alpha, mac1_r), (msg_beta, mac2_r) =
    get_macs (Noise.Message.handshake_initiation_to_cstruct msg_hs_init) in
  if not (Cstruct.equal mac1 mac1_r) then (
    print_s [%message "didn't get same mac1 as put in to handshake init!"] ;
    Cstruct.hexdump mac1 ;
    Cstruct.hexdump mac1_r ) ;
  if not (Cstruct.equal mac2 mac2_r) then (
    print_s [%message "didn't get same mac2 as put in to handshake init!"] ;
    Cstruct.hexdump mac2 ;
    Cstruct.hexdump mac2_r ) ;
  if
    not
      ( Cstruct.len msg_alpha
      = Noise.Message.sizeof_handshake_initiation - (2 * mac_size) )
  then print_s [%message "init msg_alpha is wrong length!"] ;
  if
    not
      ( Cstruct.len msg_beta
      = Noise.Message.sizeof_handshake_initiation - mac_size )
  then print_s [%message "init msg_beta is wrong length!"] ;
  let msg_hs_resp = Noise.Message.new_handshake_response () in
  Noise.Message.blit_handshake_response_mac1 msg_hs_resp
    (Cstruct.to_bytes mac1) ;
  Noise.Message.blit_handshake_response_mac2 msg_hs_resp
    (Cstruct.to_bytes mac2) ;
  let (msg_alpha, mac1_r), (msg_beta, mac2_r) =
    get_macs (Noise.Message.handshake_response_to_cstruct msg_hs_resp) in
  if not (Cstruct.equal mac1 mac1_r) then (
    print_s [%message "didn't get same mac1 as put in to handshake resp!"] ;
    Cstruct.hexdump mac1 ;
    Cstruct.hexdump mac1_r ) ;
  if not (Cstruct.equal mac2 mac2_r) then (
    print_s [%message "didn't get same mac2 as put in to handshake resp!"] ;
    Cstruct.hexdump mac2 ;
    Cstruct.hexdump mac2_r ) ;
  if
    not
      ( Cstruct.len msg_alpha
      = Noise.Message.sizeof_handshake_response - (2 * mac_size) )
  then print_s [%message "resp msg_alpha is wrong length!"] ;
  if
    not
      ( Cstruct.len msg_beta
      = Noise.Message.sizeof_handshake_response - mac_size )
  then print_s [%message "resp msg_beta is wrong length!"] ;
  [%expect {| |}]
