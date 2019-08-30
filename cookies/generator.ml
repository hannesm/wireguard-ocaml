type%cstruct t =
  { (* CR crichoux: should you add a mutex here? *)
    mac1_key: uint8_t [@len 32]
  ; mac2_cookie: uint8_t [@len 32]
  ; mac2_cookie_set: uint8_t [@len 12]
  ; mac2_has_last_mac1: uint8_t
  ; mac2_last_mac1: uint8_t [@len 32]
  ; encryption_key: uint8_t [@len 32] }
[@@little_endian]

type t = Cstruct.t
