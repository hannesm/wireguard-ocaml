open Core
open Cstruct
open Async

type stats = {tx_bytes: uint64; rx_bytes: uint64; last_handshake_nano: uint64}

type timers =
  { retransmit_handshake: Clock_ns.Event.t ref
  ; send_keepalive: Clock_ns.Event.t ref
  ; new_handshake: Clock_ns.Event.t ref
  ; zero_key_material: Clock_ns.Event.t ref
  ; persistent_keepalive: Clock_ns.Event.t ref
  ; handshake_attempts: int ref
  ; need_another_keepalive: bool ref
  ; sent_last_minute_handshake: bool ref }

type signals =
  { new_keypair_arrived: unit Deferred.t option
  ; flush_nonce_queue: unit Deferred.t option }

type queue = unit

type t =
  { (*CR crichoux: make atomic? *)
    is_running: bool ref
  ; sequencer: unit Async.Throttle.Sequencer.t
  ; keypairs: Noise.Keypair.keypairs
  ; handshake: Noise.Handshake.t
  ; endpoint: unit option
  ; persistent_keepalive_interval: uint16_t
  ; stats: stats
  ; timers: timers
  ; signals: signals
  ; queue: queue
  ; routines: routines
  ; cookie_generator: Cookies.Generator.t }
