(* size of handshake initation message *)
let msg_initiation_size = 148

(* size of response message *)
let _msg_response_size = 92

(* size of cookie reply message *)
let _msg_cookie_reply_size = 64

(* size of data preceeding content in transport message *)
let msg_transport_header_size = 16

(* size of empty transport *)
let msg_transport_size =
  msg_transport_header_size + Crypto.poly1305_tag_size

(* size of keepalive *)
let _msg_keep_alive_size = msg_transport_size

(* size of largest handshake releated message *)
let _msg_handshake_size = msg_initiation_size

(* offsets of interesting things inside transpost messages *)
let _msg_transport_offset_receiver = 4
let _msg_transport_offset_counter = 8
let _msg_transport_offset_content = 16

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

let blit_handshake_initiation_ephemeral t bytes =
  let cs = Cstruct.of_bytes bytes in
  blit_handshake_initiation_ephemeral cs 0 t

let blit_handshake_initiation_signed_static t bytes =
  let cs = Cstruct.of_bytes bytes in
  blit_handshake_initiation_signed_static cs 0 t

let blit_handshake_initiation_signed_timestamp t bytes =
  let cs = Cstruct.of_bytes bytes in
  blit_handshake_initiation_signed_timestamp cs 0 t

let get_handshake_initiation_ephemeral t =
  get_handshake_initiation_ephemeral t |> Cstruct.to_bytes

let get_handshake_initiation_signed_static t =
  get_handshake_initiation_signed_static t |> Cstruct.to_bytes

let get_handshake_initiation_signed_timestamp t =
  get_handshake_initiation_signed_timestamp t |> Cstruct.to_bytes

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

type%cstruct cookie_reply =
  { msg_type: uint32_t
  ; receiver: uint32_t
  ; nonce: uint8_t [@len 24]
  ; cookie: uint8_t [@len 48] }
[@@little_endian]

type cookie_reply = Cstruct.t

type%cstruct transport_header =
  {msg_type: uint32_t; receiver: uint32_t; counter: uint64_t}
[@@little_endian]

type transport_header = Cstruct.t
type transport = transport_header * bytes
