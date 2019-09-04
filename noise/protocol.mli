(* CR crichoux: bin_io all the messages *)

val create_message_initiation :
     ?timestamp:Tai64n.t
  -> ?local_ephemeral:Crypto.keypair
  -> local_static_public:Crypto.Public.key
  -> Handshake.t
  -> Messages.Handshake_initiation.t_cstruct Core.Or_error.t

type peer

val consume_message_initiation :
     ?peer:peer
  -> msg:Messages.Handshake_initiation.t_cstruct
  -> local_static:Crypto.keypair
  -> peer Core.Or_error.t

val create_message_response :
     ?local_ephemeral:Crypto.keypair
  -> peer
  -> Messages.Handshake_response.t_cstruct Core.Or_error.t

val consume_message_response :
     ?handshake:Handshake.t
  -> ?local_static:Crypto.keypair
  -> Messages.Handshake_response.t_cstruct
  -> peer Core.Or_error.t

val begin_symmetric_session : peer -> unit Core.Or_error.t

(* CR crichoux: what is this for again *)
(* val received_with_keypair : peer:peer -> Keypair.t -> bool *)
