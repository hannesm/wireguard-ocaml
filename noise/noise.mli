val create_message_initiation :
     ?timestamp:Tai64n.t
  -> ?local_ephemeral:Crypto.keypair
  -> local_static_public:Crypto.Public.key
  -> handshake:Handshake.t
  -> Message.handshake_initiation Core.Or_error.t

type peer

val consume_message_initiation : ?peer:peer ->
           msg:Message.handshake_initiation ->
           local_static:Crypto.keypair -> peer Core.Or_error.t
