open Cstruct

type stats
type timers
type signals
type queue
type routines

type t =
  { is_running: bool ref
  ; keypairs: Noise.Keypair.ts
  ; handshake: Noise.Handshake.t
  ; (* CR crichoux: implement devices *)
    device: unit
  ; endpoint: unit
  ; persistent_keepalive_interval: uint16
  ; stats: stats
  ; timers: timers
  ; signals: signals
  ; queue: queue
  ; routines: routines
  ; cookie_generator: Cookies.Generator.t }
