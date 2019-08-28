val create_message_initiation :
     ?timestamp:bytes
  -> ?local_ephemeral:Crypto.keypair
  -> local_static_public:Crypto.Public.key
  -> handshake:Handshake.t
  -> Message.handshake_initiation Core.Or_error.t
