type t

val init : Crypto.Public.key -> t Core.Or_error.t

(* CR crichoux: maybe make the message type-specific or something? *)
val check_macs : t -> Cstruct.t -> unit Core.Or_error.t
