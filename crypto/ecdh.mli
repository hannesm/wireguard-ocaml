open Core
open Key

val generate : unit -> keypair Or_error.t

val dh : public:public_key -> secret:secret_key -> shared_key Or_error.t
