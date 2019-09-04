open Core
open Async

(* CR crichoux: remember to run the scheduler *)

let is_pending timer =
  match Clock_ns.Event.status timer with Scheduled_at _ -> true | _ -> false

let timers_active peer =
  is_pending peer.timers.retransmit_handshake
  || is_pending peer.timers.send_keepalive
  || is_pending peer.timers.new_handshake
  || is_pending peer.timers.zero_key_material
  || is_pending peer.timers.persistent_keepalive

let expired_retransmit_handshake ~device ~peer =
  if peer.timers.handshake_attempts > max_timer_handshakes then (
    Log.debug_s device.log
      [%message
        (peer : Peer.t)
          "Handshake did not complete after max attempts, giving up."
          (max_timer_handshakes + 2 : int)] ;
    Clock_ns.Event.abort peer.timers.send_keepalive |> ignore ;
    Peer.flush_nonce_queue peer ;
    if
      Peer.has_active_timers peer
      && not (is_pending peer.timers.zero_key_material)
    then
      peer.timers.zero_key_material <-
        Clock.Event.run_after (Reject_after_time * 3) zero_key_material )
  else (
    peer.timers.handshake_attempts := peer.timers.handshake_attempts + 1 ;
    Log.debug_s device.log
      [%message
        (peer : Peer.t)
          "Handshake did not complete, retrying"
          (rekey_timeout.seconds : int)
          (peer.timers.handshake_attempts : int)] ;
    Option.value_map ~default:() ~f:clear_src peer.endpoint ;
    Peer.send_handshake_initiation peer true )

let expired_send_keepalive ~device ~peer =
  Peer.send_keepalive peer ;
  if peer.timers.need_another_keepalive then (
    peer.timers.need_another_keepalive := false ;
    if timers_active peer then
      peer.timers.send_keepalive :=
        Clock_ns.Event.run_after keepalive_timeout send_keepalive )

let expired_new_handshake ~device ~peer = failwith "unimplemented"
