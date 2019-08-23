open Core
open Key

val generate : unit -> keypair Or_error.t

val dh : public:public key -> secret:secret key -> shared key Or_error.t
