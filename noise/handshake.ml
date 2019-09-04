(* CR crichoux: sort these and clean up *)
(* CR crichoux: add finalizers *)

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

let sexp_of_noise_state ns = noise_state_to_int ns |> sexp_of_int

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

let new_handshake () =
  let buf = Bytes.make sizeof_t '\x00' in
  Cstruct.of_bytes buf

let get_t_precomputed_static_static t =
  get_t_precomputed_static_static t |> Cstruct.to_bytes

let blit_t_precomputed_static_static =
  Misc.make_nice_blit blit_t_precomputed_static_static

let get_t_preshared_key t = get_t_preshared_key t |> Cstruct.to_bytes
let get_t_remote_static t = get_t_remote_static t |> Cstruct.to_bytes
let get_t_remote_ephemeral t = get_t_remote_ephemeral t |> Cstruct.to_bytes
let blit_t_remote_static = Misc.make_nice_blit blit_t_remote_static
let blit_t_remote_ephemeral = Misc.make_nice_blit blit_t_remote_ephemeral

let get_t_local_ephemeral_public t =
  get_t_local_ephemeral_public t |> Cstruct.to_bytes

let get_t_local_ephemeral_private t =
  get_t_local_ephemeral_private t |> Cstruct.to_bytes

let get_t_hash t = get_t_hash t |> Cstruct.to_bytes
let blit_t_hash = Misc.make_nice_blit blit_t_hash
let get_t_chain_key t = get_t_chain_key t |> Cstruct.to_bytes
let blit_t_chain_key = Misc.make_nice_blit blit_t_chain_key

let blit_t_ephemeral_keypair t (keypair : Crypto.keypair) =
  Crypto.Secret.to_bytes keypair.secret
  |> (Misc.make_nice_blit blit_t_local_ephemeral_private) t ;
  Crypto.Public.to_bytes keypair.public
  |> (Misc.make_nice_blit blit_t_local_ephemeral_public) t

let get_t_last_timestamp t = get_t_last_timestamp t |> Cstruct.to_bytes
let blit_t_last_timestamp = Misc.make_nice_blit blit_t_last_timestamp

let get_t_last_initiation_consumption t =
  get_t_last_initiation_consumption t |> Cstruct.to_bytes

let blit_t_last_initiation_consumption =
  Misc.make_nice_blit blit_t_last_initiation_consumption

let zero_t_chain_key t = blit_t_chain_key t (Bytes.make 32 '\x00')
let zero_t_hash t = blit_t_hash t (Bytes.make 32 '\x00')

let zero_t_local_ephemeral t =
  blit_t_local_ephemeral_private (Bytes.make 32 '\x00' |> Cstruct.of_bytes) 0 t ;
  blit_t_local_ephemeral_public (Bytes.make 32 '\x00' |> Cstruct.of_bytes) 0 t

(* ok_exn safe because you can only set this from the outside w/ set_t_state *)
let get_t_state t = get_t_state t |> int_to_noise_state |> Option.value_exn
let set_t_state t state = set_t_state t (noise_state_to_int state)

open Or_error.Let_syntax

let mix_key handshake bytes : unit =
  let c_i = kdf_1 ~key:(Shared.of_bytes (get_t_chain_key handshake)) bytes in
  blit_t_chain_key handshake (Shared.to_bytes c_i)

let mix_key2 handshake bytes : Shared.key =
  let c_i, kappa =
    kdf_2 ~key:(Shared.of_bytes (get_t_chain_key handshake)) bytes in
  blit_t_chain_key handshake (Shared.to_bytes c_i) ;
  kappa

let mix_key3 handshake bytes : Shared.key * Shared.key =
  let c_i, tau, kappa =
    kdf_3 ~key:(Shared.of_bytes (get_t_chain_key handshake)) bytes in
  blit_t_chain_key handshake (Shared.to_bytes c_i) ;
  (tau, kappa)

let mix_hash handshake bytes : unit Or_error.t =
  let%map result = hash2 (get_t_hash handshake) bytes in
  blit_t_hash handshake result
