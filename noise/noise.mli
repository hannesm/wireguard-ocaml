open Core
open Crypto

module Noise_message : sig
  type t
end

module Handshake : sig
  type t
end

val create_message_initiation :
     local_static_public:Public.key
  -> handshake:Handshake.t
  -> Noise_message.t Or_error.t
