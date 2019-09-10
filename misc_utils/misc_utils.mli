val make_nice_blit : (Cstruct.t -> int -> 'a -> unit) -> 'a -> bytes -> unit

module Rwlock : sig
  type t

  val create : unit -> t
  val read_lock : t -> unit
  val read_unlock : t -> unit
  val write_lock : t -> unit
  val write_unlock : t -> unit
end
