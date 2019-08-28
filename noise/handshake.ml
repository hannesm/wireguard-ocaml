open Core
open Crypto

type t = Cstruct.t

type%cenum noise_state =
  | Handshake_zeroed
  | Handshake_initiation_created
  | Handshake_initiation_consumed
  | Handshake_response_created
  | Handshake_response_consumed
[@@uint8_t]

type%cstruct t =
  { state: uint8_t
  ; (* CR crichoux: add this back? -> mutex : sync.RWMutex *)
    hash: uint8_t [@len 32]
  ; chain_key: uint8_t [@len 32]
  ; preshared_key: uint8_t [@len 32]
  ; local_ephemeral_private: uint8_t [@len 32]
  ; local_ephemeral_public: uint8_t [@len 32]
  ; (* localIndex is used to clear hash-table *)
    local_index: uint32_t
  ; remote_index: uint32_t
  ; remote_static: uint8_t [@len 32]
  ; remote_ephemeral: uint8_t [@len 32]
  ; precomputed_static_static: uint8_t [@len 32]
  ; last_timestamp: uint8_t [@len 12]
  ; last_initiation_consumption: uint8_t [@len 12]
  ; last_sent_handshake: uint8_t [@len 12] }
[@@little_endian]

let new_handshake () = Cstruct.create sizeof_t

let get_t_precomputed_static_static t =
  get_t_precomputed_static_static t |> Cstruct.to_bytes

let blit_t_precomputed_static_static t bytes =
  let cs = Cstruct.of_bytes bytes in
  blit_t_precomputed_static_static cs 0 t

let get_t_remote_static t = get_t_remote_static t |> Cstruct.to_bytes

let blit_t_remote_static t bytes =
  let cs = Cstruct.of_bytes bytes in
  blit_t_remote_static cs 0 t

let get_t_local_ephemeral_public t =
  get_t_local_ephemeral_public t |> Cstruct.to_bytes

let get_t_local_ephemeral_private t =
  get_t_local_ephemeral_private t |> Cstruct.to_bytes

let get_t_hash t = get_t_hash t |> Cstruct.to_bytes

let blit_t_hash t bytes =
  let cs = Cstruct.of_bytes bytes in
  blit_t_hash cs 0 t

let get_t_chain_key t = get_t_chain_key t |> Cstruct.to_bytes

let blit_t_chain_key t bytes =
  let cs = Cstruct.of_bytes bytes in
  blit_t_chain_key cs 0 t

let blit_t_ephemeral_keypair t (keypair : Crypto.keypair) =
  let cs = Crypto.Secret.to_bytes keypair.secret |> Cstruct.of_bytes in
  blit_t_local_ephemeral_private cs 0 t ;
  let cs = Crypto.Public.to_bytes keypair.public |> Cstruct.of_bytes in
  blit_t_local_ephemeral_public cs 0 t

open Or_error.Let_syntax

let mix_key handshake bytes : unit =
  let c_i = kdf_1 ~key:(Shared.of_bytes (get_t_chain_key handshake)) bytes in
  blit_t_chain_key handshake (Shared.to_bytes c_i)

let mix_key2 handshake bytes : Shared.key =
  let c_i, kappa =
    kdf_2 ~key:(Shared.of_bytes (get_t_chain_key handshake)) bytes in
  blit_t_chain_key handshake (Shared.to_bytes c_i) ;
  kappa

let mix_hash handshake bytes : unit Or_error.t =
  let%map result = hash2 (get_t_hash handshake) bytes in
  blit_t_hash handshake result
