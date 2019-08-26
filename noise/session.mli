type t

val create : local_index:int32 -> peer_index:int32 -> receiving_key:bytes -> sending_key:bytes -> t

val local_index : t -> int32

(*
  let format_packet_data = failwith "unimplemented"
pub(super) fn receive_packet_data<'a>(
*)
