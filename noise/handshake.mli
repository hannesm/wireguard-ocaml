(* CR crichoux: sort these lol *)

open Core
open Cstruct

type t

type noise_state =
  | Handshake_zeroed
  | Handshake_initiation_created
  | Handshake_initiation_consumed
  | Handshake_response_created
  | Handshake_response_consumed
[@@deriving sexp_of]

(* CR crichoux: error handling? *)
val hexdump_t : t -> unit
val new_handshake : unit -> t
val get_t_precomputed_static_static : t -> bytes
val get_t_remote_static : t -> bytes
val get_t_remote_ephemeral : t -> bytes
val get_t_local_ephemeral_public : t -> bytes
val get_t_local_ephemeral_private : t -> bytes
val get_t_hash : t -> bytes
val get_t_chain_key : t -> bytes
val get_t_last_timestamp : t -> bytes
val get_t_last_initiation_consumption : t -> bytes
val get_t_preshared_key : t -> bytes
val get_t_state : t -> noise_state
val get_t_local_index : t -> uint32
val get_t_remote_index : t -> uint32
val blit_t_precomputed_static_static : t -> bytes -> unit
val blit_t_remote_static : t -> bytes -> unit
val blit_t_hash : t -> bytes -> unit
val blit_t_chain_key : t -> bytes -> unit
val blit_t_ephemeral_keypair : t -> Crypto.keypair -> unit
val blit_t_remote_ephemeral : t -> bytes -> unit
val blit_t_last_timestamp : t -> bytes -> unit
val blit_t_last_initiation_consumption : t -> bytes -> unit
val set_t_state : t -> noise_state -> unit
val set_t_local_index : t -> uint32 -> unit
val set_t_remote_index : t -> uint32 -> unit
val zero_t_chain_key : t -> unit
val zero_t_hash : t -> unit
val zero_t_local_ephemeral : t -> unit
val mix_key : t -> bytes -> unit
val mix_key2 : t -> bytes -> Crypto.Shared.key
val mix_key3 : t -> bytes -> Crypto.Shared.key * Crypto.Shared.key
val mix_hash : t -> bytes -> unit Or_error.t
