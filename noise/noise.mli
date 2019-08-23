val first_message :
     msg_sender:bytes
  -> timestamp:bytes
  -> e_i:Nacl_crypto.Key.keypair
  -> s_r_public:bytes
  -> s_i:Nacl_crypto.Key.keypair
  -> ((bytes * bytes) * bytes) Core.Or_error.t

val second_message :
     ?q:bytes
  -> incoming_packet:bytes
  -> msg_receiver:bytes
  -> e_r:Nacl_crypto.Key.keypair
  -> s_r:Nacl_crypto.Key.keypair
  -> s_i_public:bytes
  -> ((bytes * bytes) * bytes) Core.Or_error.t
