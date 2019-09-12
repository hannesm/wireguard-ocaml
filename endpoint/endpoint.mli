open Core

type t = {src: Unix.Inet_addr.t ref; dst: Unix.Inet_addr.t ref}

val clear_src : t -> unit
val dst_to_bytes : t -> bytes
