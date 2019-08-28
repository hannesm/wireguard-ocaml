type handshake_initiation
type handshake_response
type cookie_reply
type transport_header
type transport

val hexdump_handshake_initiation : handshake_initiation -> unit
val new_handshake_initiation : unit -> handshake_initiation

val set_handshake_initiation_sender :
  handshake_initiation -> Cstruct.uint32 -> unit

val blit_handshake_initiation_ephemeral :
  handshake_initiation -> bytes -> unit

val blit_handshake_initiation_signed_static :
  handshake_initiation -> bytes -> unit

val blit_handshake_initiation_signed_timestamp :
  handshake_initiation -> bytes -> unit
