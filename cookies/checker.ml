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

let blit_t_mac1_key = Misc.make_nice_blit blit_t_mac1_key
let blit_t_mac2_secret = Misc.make_nice_blit blit_t_mac2_secret
let blit_t_mac2_secret_set = Misc.make_nice_blit blit_t_mac2_secret_set
let blit_t_mac2_encryption_key = Misc.make_nice_blit blit_t_mac2_encryption_key

let get_t_mac1_key t =
  get_t_mac1_key t |> Cstruct.to_bytes |> Crypto.Shared.of_bytes

let get_t_mac2_secret t =
  get_t_mac2_secret t |> Cstruct.to_bytes |> Crypto.Shared.of_bytes

let get_t_mac2_secret_set t =
  get_t_mac2_secret_set t |> Cstruct.to_bytes |> Tai64n.of_bytes

let get_t_mac2_encryption_key t =
  get_t_mac2_encryption_key t |> Cstruct.to_bytes |> Crypto.Shared.of_bytes

let init pk : t Or_error.t =
  let ckr = Cstruct.create sizeof_t in
  let%map mac1_key, mac2_encryption_key, time = Misc.init_constants pk in
  blit_t_mac1_key ckr mac1_key ;
  blit_t_mac2_encryption_key ckr mac2_encryption_key ;
  blit_t_mac2_secret_set ckr time ;
  ckr

let check_mac1 ~t ~(msg_alpha : Cstruct.t) ~(mac1_r : Cstruct.t) :
    unit Or_error.t =
  let%bind mac1 =
    Crypto.mac ~key:(get_t_mac1_key t) ~input:(Cstruct.to_bytes msg_alpha)
    >>| Cstruct.of_bytes in
  Result.ok_if_true
    ~error:(Error.of_string "mac1 check failed!")
    (Cstruct.equal mac1 mac1_r)

(* src is concatenation of external IP src address and UDP port *)
let check_mac2 ~t ~(msg_beta : Cstruct.t) ~(mac2_r : Cstruct.t) ~(src : bytes)
    : unit Or_error.t =
  let%bind () =
    let mac2_secret_set = get_t_mac2_secret_set t in
    Result.ok_if_true
      (Tai64n.since mac2_secret_set <= Misc.cookie_refresh_time)
      ~error:(Error.of_string "cookie expired") in
  let%bind cookie =
    Crypto.mac ~key:(get_t_mac2_secret t) ~input:src >>| Crypto.Shared.of_bytes
  in
  let%bind mac2 =
    Crypto.mac ~key:cookie ~input:(Cstruct.to_bytes msg_beta)
    >>| Cstruct.of_bytes in
  Result.ok_if_true
    ~error:(Error.of_string "mac2 check failed!")
    (Cstruct.equal mac2 mac2_r)

let check_macs ~t ~msg ~src : unit Or_error.t =
  let (msg_alpha, mac1_r), (msg_beta, mac2_r) =
    Misc.get_macs (Noise.Message.handshake_response_to_cstruct msg) in
  let%bind () = check_mac1 ~t ~msg_alpha ~mac1_r in
  check_mac2 ~t ~msg_beta ~mac2_r ~src

(* msg is incoming message prompting cookie reply msg *)
(* recv is receiver id from msg.sender of message *)
(* src is concatenation of external IP src address and UDP port *)
(* CR crichoux: write expect tests for this! *)
let create_reply ~t ~msg ~recv ~src : Noise.Message.cookie_reply Or_error.t =
  let mac2_secret_set = get_t_mac2_secret_set t in
  if Time_ns.Span.(Tai64n.since mac2_secret_set <= Misc.cookie_refresh_time)
  then (
    (* CR crichoux: mutex stuff here *)
    blit_t_mac2_secret t (Crypto.random_buffer 32) ;
    blit_t_mac2_secret_set t (Tai64n.now () |> Tai64n.to_bytes) ) ;
  let%bind tau = Crypto.mac ~key:(get_t_mac2_secret t) ~input:src in
  let (_, mac1_r), _ =
    Misc.get_macs (Noise.Message.handshake_response_to_cstruct msg) in
  let reply = Noise.Message.new_cookie_reply () in
  Noise.Message.set_cookie_reply_receiver reply recv ;
  let nonce = Crypto.random_buffer 24 in
  Noise.Message.blit_cookie_reply_nonce reply nonce ;
  let%map cookie =
    Crypto.xaead_encrypt
      ~key:(get_t_mac2_encryption_key t)
      ~nonce ~message:tau
      ~auth_text:(mac1_r |> Cstruct.to_bytes) in
  Noise.Message.blit_cookie_reply_cookie reply cookie ;
  reply
