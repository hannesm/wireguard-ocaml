open Core

type t = {src: Unix.Inet_addr.t ref; dst: Unix.Inet_addr.t ref}

let clear_src t = t.src <- nil
let dst_to_bytes dst = failwith "unimplemented"
