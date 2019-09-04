module Handshake_initiation = struct include Handshake_initiation end
module Handshake_response = struct include Handshake_response end
module Cookie_reply = struct include Cookie_reply end
module Transport = struct include Transport end

type mac_message =
  | Handshake_initiation of Handshake_initiation.t
  | Handshake_response of Handshake_response.t
  | Handshake_initiation_cstruct of Handshake_initiation.t_cstruct
  | Handshake_response_cstruct of Handshake_response.t_cstruct

let get_macs (msg : mac_message) =
  let get_macs_init (m : Handshake_initiation.t) =
    (m.msg_alpha, !(m.mac1), m.msg_beta, !(m.mac2)) in
  let get_macs_resp (m : Handshake_response.t) =
    (m.msg_alpha, !(m.mac1), m.msg_beta, !(m.mac2)) in
  match msg with
  | Handshake_initiation m -> get_macs_init m
  | Handshake_response m -> get_macs_resp m
  | Handshake_initiation_cstruct m_cstruct ->
      Handshake_initiation.cstruct_to_t m_cstruct |> get_macs_init
  | Handshake_response_cstruct m_cstruct ->
      Handshake_response.cstruct_to_t m_cstruct |> get_macs_resp

let set_macs ~(msg : mac_message) ~mac1 ~mac2 =
  match msg with
  | Handshake_initiation m ->
      m.mac1 := mac1 ;
      m.mac2 := mac2
  | Handshake_response m ->
      m.mac1 := mac1 ;
      m.mac2 := mac2
  | Handshake_initiation_cstruct m_cstruct ->
      Handshake_initiation.set_macs ~msg:m_cstruct ~mac1 ~mac2
  | Handshake_response_cstruct m_cstruct ->
      Handshake_response.set_macs ~msg:m_cstruct ~mac1 ~mac2

type t =
  | Handshake_initiation of Handshake_initiation.t
  | Handshake_response of Handshake_response.t
  | Cookie_reply of Cookie_reply.t
  | Transport of Transport.t
