(* CR crichoux: sort these lol *)

(* size of handshake initation message *)
let msg_initiation_size = 148

(* size of response message *)
let _msg_response_size = 92

(* size of cookie reply message *)
let _msg_cookie_reply_size = 64

(* size of data preceeding content in transport message *)
let msg_transport_header_size = 16

(* size of empty transport *)
let msg_transport_size = msg_transport_header_size + Crypto.poly1305_tag_size

(* size of keepalive *)
let _msg_keep_alive_size = msg_transport_size

(* size of largest handshake releated message *)
let _msg_handshake_size = msg_initiation_size

(* offsets of interesting things inside transpost messages *)
let _msg_transport_offset_receiver = 4
let _msg_transport_offset_counter = 8
let _msg_transport_offset_content = 16

let make_nice_blit func t bytes =
  let cs = Cstruct.of_bytes bytes in
  func cs 0 t

type%cenum message_type =
  | HANDSHAKE_INITIATION [@id 1]
  | HANDSHAKE_RESPONSE [@id 2]
  | COOKIE_REPLY [@id 3]
  | TRANSPORT [@id 4]
[@@uint32_t]

type%cstruct handshake_initiation =
  { msg_type: uint32_t
  ; sender: uint32_t
  ; ephemeral: uint8_t [@len 32]
  ; signed_static: uint8_t [@len 48]
  ; signed_timestamp: uint8_t [@len 28]
  ; mac1: uint8_t [@len 32]
  ; mac2: uint8_t [@len 32] }
[@@little_endian]

type handshake_initiation = Cstruct.t

let new_handshake_initiation () =
  let ret = Cstruct.create sizeof_handshake_initiation in
  set_handshake_initiation_msg_type ret
    (message_type_to_int HANDSHAKE_INITIATION) ;
  ret

let blit_handshake_initiation_ephemeral =
  make_nice_blit blit_handshake_initiation_ephemeral

let blit_handshake_initiation_signed_static =
  make_nice_blit blit_handshake_initiation_signed_static

let blit_handshake_initiation_signed_timestamp =
  make_nice_blit blit_handshake_initiation_signed_timestamp

let blit_handshake_initiation_mac1 =
  make_nice_blit blit_handshake_initiation_mac1

let blit_handshake_initiation_mac2 =
  make_nice_blit blit_handshake_initiation_mac2

let get_handshake_initiation_ephemeral t =
  get_handshake_initiation_ephemeral t |> Cstruct.to_bytes

let get_handshake_initiation_signed_static t =
  get_handshake_initiation_signed_static t |> Cstruct.to_bytes

let get_handshake_initiation_signed_timestamp t =
  get_handshake_initiation_signed_timestamp t |> Cstruct.to_bytes

let handshake_initiation_to_cstruct t = t

type%cstruct handshake_response =
  { msg_type: uint32_t
  ; sender: uint32_t
  ; receiver: uint32_t
  ; ephemeral: uint8_t [@len 32]
  ; signed_empty: uint8_t [@len 16]
  ; mac1: uint8_t [@len 32]
  ; mac2: uint8_t [@len 32] }
[@@little_endian]

type handshake_response = Cstruct.t

let new_handshake_response () =
  let ret = Cstruct.create sizeof_handshake_response in
  set_handshake_response_msg_type ret (message_type_to_int HANDSHAKE_RESPONSE) ;
  ret

let blit_handshake_response_mac1 = make_nice_blit blit_handshake_response_mac1
let blit_handshake_response_mac2 = make_nice_blit blit_handshake_response_mac2

let blit_handshake_response_ephemeral =
  make_nice_blit blit_handshake_response_ephemeral

let get_handshake_response_signed_empty t =
  get_handshake_response_signed_empty t |> Cstruct.to_bytes

let blit_handshake_response_signed_empty =
  make_nice_blit blit_handshake_response_signed_empty

let get_handshake_response_ephemeral t =
  get_handshake_response_ephemeral t |> Cstruct.to_bytes

let handshake_response_to_cstruct t = t

type%cstruct cookie_reply =
  { msg_type: uint32_t
  ; receiver: uint32_t
  ; nonce: uint8_t [@len 24]
  ; cookie: uint8_t [@len 48] }
[@@little_endian]

type cookie_reply = Cstruct.t

let new_cookie_reply () =
  let ret = Cstruct.create sizeof_cookie_reply in
  set_cookie_reply_msg_type ret (message_type_to_int COOKIE_REPLY) ;
  ret

let blit_cookie_reply_nonce = make_nice_blit blit_cookie_reply_nonce
let blit_cookie_reply_cookie = make_nice_blit blit_cookie_reply_cookie
let get_cookie_reply_nonce t = get_cookie_reply_nonce t |> Cstruct.to_bytes
let get_cookie_reply_cookie t = get_cookie_reply_cookie t |> Cstruct.to_bytes

type%cstruct transport_header =
  {msg_type: uint32_t; receiver: uint32_t; counter: uint64_t}
[@@little_endian]

type transport_header = Cstruct.t
type transport = transport_header * bytes
