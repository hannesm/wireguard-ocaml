type handshake_initiation
type handshake_response
type cookie_reply
type transport_header
type transport

(* CR crichoux: sort these lol *)

val hexdump_handshake_initiation : handshake_initiation -> unit
val new_handshake_initiation : unit -> handshake_initiation

val set_handshake_initiation_sender :
  handshake_initiation -> Cstruct.uint32 -> unit

val get_handshake_initiation_sender : handshake_initiation -> Cstruct.uint32
val blit_handshake_initiation_ephemeral : handshake_initiation -> bytes -> unit

val blit_handshake_initiation_signed_static :
  handshake_initiation -> bytes -> unit

val blit_handshake_initiation_signed_timestamp :
  handshake_initiation -> bytes -> unit

val get_handshake_initiation_ephemeral : handshake_initiation -> bytes
val get_handshake_initiation_signed_static : handshake_initiation -> bytes
val get_handshake_initiation_signed_timestamp : handshake_initiation -> bytes
val hexdump_handshake_response : handshake_response -> unit
val new_handshake_response : unit -> handshake_response

val set_handshake_response_sender :
  handshake_response -> Cstruct.uint32 -> unit

val get_handshake_response_sender : handshake_response -> Cstruct.uint32

val set_handshake_response_receiver :
  handshake_response -> Cstruct.uint32 -> unit

val get_handshake_response_receiver : handshake_response -> Cstruct.uint32
val get_handshake_response_ephemeral : handshake_response -> bytes
val get_handshake_response_signed_empty : handshake_response -> bytes
val blit_handshake_response_ephemeral : handshake_response -> bytes -> unit
val blit_handshake_response_signed_empty : handshake_response -> bytes -> unit
