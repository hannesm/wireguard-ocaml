val first_message
  :  msg_sender:bytes
  -> timestamp:bytes
  -> e_i:Nacl_crypto.Key.keypair
  -> s_r:bytes
  -> s_i:Nacl_crypto.Key.keypair
  -> ((bytes * bytes) * bytes) Base.Or_error.t
