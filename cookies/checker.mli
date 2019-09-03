type t

val init : Crypto.Public.key -> t Core.Or_error.t

val check_macs :
     t:t
  -> msg:Noise.Message.handshake_response
  -> src:bytes
  -> unit Core.Or_error.t

(* CR crichoux: maybe make the message type-specific or something? *)
val create_reply :
     t:t
  -> msg:Noise.Message.handshake_response
  -> recv:int32
  -> src:bytes
  -> Noise.Message.cookie_reply Core.Or_error.t
