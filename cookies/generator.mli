open Core

type t

val init : Crypto.Public.key -> t Or_error.t

val consume_reply :
  t:t -> msg:Noise.Message.cookie_reply -> unit Core.Or_error.t

val add_macs :
  t:t -> msg:Noise.Message.handshake_response -> unit Core.Or_error.t
