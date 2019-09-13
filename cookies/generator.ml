open Core
open Or_error.Let_syntax

type%cstruct t =
  { (* CR crichoux: should you add a mutex here? *)
    mac1_key: uint8_t [@len 32]
  ; mac2_cookie: uint8_t [@len 32]
  ; mac2_cookie_set: uint8_t [@len 12]
  ; mac2_has_last_mac1: uint8_t
  ; mac2_last_mac1: uint8_t [@len 16]
  ; encryption_key: uint8_t [@len 32] }
[@@little_endian]

type t = Cstruct.t

let blit_t_mac1_key = Misc_utils.make_nice_blit blit_t_mac1_key
let blit_t_encryption_key = Misc_utils.make_nice_blit blit_t_encryption_key
let blit_t_mac2_cookie_set = Misc_utils.make_nice_blit blit_t_mac2_cookie_set
let blit_t_mac2_cookie = Misc_utils.make_nice_blit blit_t_mac2_cookie
let blit_t_mac2_last_mac1 = Misc_utils.make_nice_blit blit_t_mac2_last_mac1

let get_t_mac2_cookie_set t =
  get_t_mac2_cookie_set t |> Cstruct.to_bytes |> Tai64n.of_bytes

let get_t_mac2_cookie t =
  get_t_mac2_cookie t |> Cstruct.to_bytes |> Crypto.Shared.of_bytes

let get_t_mac2_has_last_mac1 t : bool =
  match get_t_mac2_has_last_mac1 t with 1 -> true | _ -> false

let set_t_mac2_has_last_mac1 t value : unit =
  let value = if value then 1 else 0 in
  set_t_mac2_has_last_mac1 t value

let get_t_mac1_key t =
  get_t_mac1_key t |> Cstruct.to_bytes |> Crypto.Shared.of_bytes

let get_t_encryption_key t =
  get_t_encryption_key t |> Cstruct.to_bytes |> Crypto.Shared.of_bytes

let init pk : t Or_error.t =
  let ckr = Cstruct.create sizeof_t in
  let%map mac1_key, mac2_encryption_key, time = Constants.init_constants pk in
  blit_t_mac1_key ckr mac1_key ;
  blit_t_encryption_key ckr mac2_encryption_key ;
  blit_t_mac2_cookie_set ckr time ;
  ckr

(* CR crichoux: write tESTS *)
let consume_reply ~t ~(msg : Messages.Cookie_reply.t_cstruct) : unit Or_error.t
    =
  let msg = Messages.Cookie_reply.cstruct_to_t msg in
  if not (get_t_mac2_has_last_mac1 t) then
    Or_error.error_string "no last mac1 for cookie reply"
  else
    let%map cookie =
      Crypto.xaead_encrypt ~key:(get_t_encryption_key t) ~nonce:msg.nonce
        ~message:msg.cookie
        ~auth_text:(get_t_mac2_last_mac1 t |> Cstruct.to_bytes) in
    blit_t_mac2_cookie_set t (Tai64n.now () |> Tai64n.to_bytes) ;
    blit_t_mac2_cookie t cookie

(* CR crichoux: write tESTS *)
let add_macs ~t ~(msg : Messages.mac_message) : unit Or_error.t =
  let msg_alpha, _, msg_beta, _ = Messages.get_macs msg in
  let%bind mac1 =
    Crypto.mac ~key:(get_t_mac1_key t) ~input:(Cstruct.to_bytes msg_alpha)
  in
  blit_t_mac2_last_mac1 t mac1 ;
  set_t_mac2_has_last_mac1 t true ;
  let%map mac2 =
    if
      Time_ns.Span.(
        Tai64n.since (get_t_mac2_cookie_set t) > Constants.cookie_refresh_time)
    then Bytes.make 32 '\x00' |> Or_error.return
    else
      Crypto.mac ~key:(get_t_mac2_cookie t) ~input:(Cstruct.to_bytes msg_beta)
  in
  Messages.set_macs ~msg ~mac1 ~mac2
