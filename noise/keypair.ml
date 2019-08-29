type replay = unit

type t =
  { send_nonce: Cstruct.uint64
  ; send: Crypto.Shared.key
  ; receive: Crypto.Shared.key
  ; replay_filter: replay
  ; is_initiator: bool
  ; created: Time_ns.t
  ; local_index: uint32
  ; remote_index: uint32 }

type ts =
  { (* CR crichoux: do i need a mutex here? check the go impl in
       device/keypair.go, there's more interesting stuff! *)
    current: t option
  ; previous: t option
  ; next: t option }
