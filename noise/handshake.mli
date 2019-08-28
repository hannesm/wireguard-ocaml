open Core
open Cstruct

type t

(* CR crichoux: error handling? *)
val new_handshake : unit -> t
val get_t_precomputed_static_static : t -> bytes
val get_t_remote_static : t -> bytes
val get_t_local_ephemeral_public : t -> bytes
val get_t_local_ephemeral_private : t -> bytes
val get_t_hash : t -> bytes
val get_t_chain_key : t -> bytes
val blit_t_precomputed_static_static : t -> bytes -> unit
val blit_t_remote_static : t -> bytes -> unit
val blit_t_hash : t -> bytes -> unit
val blit_t_chain_key : t -> bytes -> unit
val blit_t_ephemeral_keypair : t -> Crypto.keypair -> unit
val set_t_local_index : t -> uint32 -> unit
val mix_key : t -> bytes -> unit
val mix_key2 : t -> bytes -> Crypto.Shared.key
val mix_hash : t -> bytes -> unit Or_error.t

[%%cenum
type noise_state =
  | Handshake_zeroed
  | Handshake_initiation_created
  | Handshake_initiation_consumed
  | Handshake_response_created
  | Handshake_response_consumed
[@@uint8_t]]
