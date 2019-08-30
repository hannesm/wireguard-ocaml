open Core
open Or_error.Let_syntax

type%cstruct t =
  { (* CR crichoux: should you add a mutex here? *)
    mac1_key: uint8_t [@len 32]
  ; mac2_secret: uint8_t [@len 32]
  ; mac2_secret_set: uint8_t [@len 12]
  ; mac2_encryption_key: uint8_t [@len 32] }
[@@little_endian]

type t = Cstruct.t

let make_nice_blit func t bytes =
  let cs = Cstruct.of_bytes bytes in
  func cs 0 t

let blit_t_mac1_key = make_nice_blit blit_t_mac1_key
let _blit_t_mac2_secret = make_nice_blit blit_t_mac2_secret
let blit_t_mac2_secret_set = make_nice_blit blit_t_mac2_secret_set
let blit_t_mac2_encryption_key = make_nice_blit blit_t_mac2_encryption_key

let get_t_mac1_key t =
  get_t_mac1_key t |> Cstruct.to_bytes |> Crypto.Shared.of_bytes

let _get_t_mac2_secret_set t =
  get_t_mac2_secret_set t |> Cstruct.to_bytes |> Tai64n.of_bytes

let init pubkey : t Or_error.t =
  let open Crypto in
  let ckr = Cstruct.create sizeof_t in
  let pk_bytes = Public.to_bytes pubkey in
  let%bind mac1_key = hash2 Constants.wg_label_mac1 pk_bytes in
  blit_t_mac1_key ckr mac1_key ;
  let%map mac2_encryption_key = hash2 Constants.wg_label_cookie pk_bytes in
  blit_t_mac2_encryption_key ckr mac2_encryption_key ;
  blit_t_mac2_secret_set ckr (Tai64n.now () |> Tai64n.to_bytes) ;
  ckr

let get_macs msg : (Cstruct.t * Cstruct.t) * (Cstruct.t * Cstruct.t) =
  let size = Cstruct.len msg in
  let msg_alpha, mac1 =
    let msg_alpha, macs = Cstruct.split msg (size - (2 * Constants.mac_size)) in
    (msg_alpha, Cstruct.sub macs 0 Constants.mac_size) in
  let msg_beta, mac2 = Cstruct.split msg (size - Constants.mac_size) in
  ((msg_alpha, mac1), (msg_beta, mac2))

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
      = Noise.Message.sizeof_handshake_initiation - (2 * Constants.mac_size) )
  then print_s [%message "init msg_alpha is wrong length!"] ;
  if
    not
      ( Cstruct.len msg_beta
      = Noise.Message.sizeof_handshake_initiation - Constants.mac_size )
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
      = Noise.Message.sizeof_handshake_response - (2 * Constants.mac_size) )
  then print_s [%message "resp msg_alpha is wrong length!"] ;
  if
    not
      ( Cstruct.len msg_beta
      = Noise.Message.sizeof_handshake_response - Constants.mac_size )
  then print_s [%message "resp msg_beta is wrong length!"] ;
  [%expect {| |}]

let check_mac1 ~t ~(msg_alpha : Cstruct.t) ~(mac1_r : Cstruct.t) :
    unit Or_error.t =
  let%bind mac1 =
    Crypto.mac ~key:(get_t_mac1_key t) ~input:(Cstruct.to_bytes msg_alpha)
    >>| Cstruct.of_bytes in
  Result.ok_if_true
    ~error:(Error.of_string "mac1 check failed!")
    (Cstruct.equal mac1 mac1_r)

let check_mac2 ~_t ~_msg_beta ~_mac2_r : unit Or_error.t =
  failwith "unimplemented"

(*let%bind () = Result.ok_if_true ~error:(Error.of_string "cookie expired")
  Tai64n.since (get_t_msg_secret_set t) in let%bind mac2 = Crypto.mac
  ~key:(get_t_mac2_secret t) ~input:msg_alpha >>| Cstruct.of_bytes in
  Result.ok_if_true ~error:(Error.of_string "mac1 check failed!")
  (Cstruct.equal mac1 mac1_r)*)

let check_macs t msg : unit Or_error.t =
  let (msg_alpha, mac1_r), (msg_beta, mac2_r) = get_macs msg in
  let%bind () = check_mac1 ~t ~msg_alpha ~mac1_r in
  check_mac2 ~_t:t ~_msg_beta:msg_beta ~_mac2_r:mac2_r

let create_cookie_reply t ~msg ~recv ~src : Noise.Message.cookie_reply =
