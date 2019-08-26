open Core


(* type noise_state =
  | Handshake_zeroed
  | Handshake_initiation_created
  | Handshake_initiation_consumed
  | Handshake_response_created
  | Handshake_response_consumed*)

let _noise_construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
let _wg_identifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
let _wg_label_MAC1       = "mac1----"
let _wg_label_cookie     = "cookie--"

(* initiator.chaining_key = HASH(CONSTRUCTION)*)
let initial_chain_key =
  Bytes.of_string
    "\x60\xe2\x6d\xae\xf3\x27\xef\xc0\x2e\xc3\x35\xe2\xa0\x25\xd2\xd0\x16\xeb\x42\x06\xf8\x72\x77\xf5\x2d\x38\xd1\x98\x8b\x78\xcd\x36"

(* initiator.chaining_hash = HASH(initiator.chaining_key || IDENTIFIER) *)
let initial_chain_hash =
  Bytes.of_string
    "\x22\x11\xb3\x61\x08\x1a\xc5\x66\x69\x12\x43\xdb\x45\x8a\xd5\x32\x2d\x9c\x6c\x66\x22\x93\xe8\xb7\x0e\xe1\x9c\x65\xba\x07\x9e\xf3"

let _add_macs ~message ~message_length =
  assert (Bytes.length message = message_length + 32) ;
  failwith "unimplemented"

let bytes_to_hex (bytes : bytes) : string =
  Hex.hexdump_s ~print_row_numbers:false ~print_chars:false
    (bytes |> Bytes.to_string |> Hex.of_string)

let first_message_of_fields ~msg_sender ~msg_ephemeral ~msg_static_signed
    ~msg_timestamp_signed =
  assert (Bytes.length msg_sender = 4) ;
  assert (Bytes.length msg_ephemeral = 32) ;
  assert (Bytes.length msg_static_signed = 48) ;
  assert (Bytes.length msg_timestamp_signed = 28) ;
  let buf = Bytes.create 148 in
  let msg_type_and_reserved = Bytes.of_string "\x01\x00\x00\x00" in
  Bytes.blit ~src:msg_type_and_reserved ~src_pos:0 ~dst:buf ~dst_pos:0
    ~len:4 ;
  Bytes.blit ~src:msg_sender ~src_pos:0 ~dst:buf ~dst_pos:4 ~len:4 ;
  Bytes.blit ~src:msg_ephemeral ~src_pos:0 ~dst:buf ~dst_pos:8 ~len:32 ;
  Bytes.blit ~src:msg_static_signed ~src_pos:0 ~dst:buf ~dst_pos:40 ~len:48 ;
  Bytes.blit ~src:msg_timestamp_signed ~src_pos:0 ~dst:buf ~dst_pos:88
    ~len:28 ;
  buf

let _second_message_of_fields ~msg_sender ~msg_receiver ~msg_ephemeral
    ~msg_empty =
  assert (Bytes.length msg_sender = 4) ;
  assert (Bytes.length msg_receiver = 4) ;
  assert (Bytes.length msg_ephemeral = 32) ;
  assert (Bytes.length msg_empty = 12) ;
  let buf = Bytes.create 92 in
  let msg_type_and_reserved = Bytes.of_string "\x02\x00\x00\x00" in
  Bytes.blit ~src:msg_type_and_reserved ~src_pos:0 ~dst:buf ~dst_pos:0
    ~len:4 ;
  Bytes.blit ~src:msg_sender ~src_pos:0 ~dst:buf ~dst_pos:4 ~len:4 ;
  Bytes.blit ~src:msg_receiver ~src_pos:0 ~dst:buf ~dst_pos:8 ~len:4 ;
  Bytes.blit ~src:msg_ephemeral ~src_pos:0 ~dst:buf ~dst_pos:12 ~len:32 ;
  Bytes.blit ~src:msg_empty ~src_pos:0 ~dst:buf ~dst_pos:44 ~len:16 ;
  buf

let first_message ~(msg_sender : bytes) ~(timestamp : bytes)
    ~(e_i : Crypto.Key.keypair)
    ~(s_r_public : Crypto.Key.public_key)
    ~(s_i : Crypto.Key.keypair) : ((Crypto.Key.shared_key * bytes) * bytes) Or_error.t
    =
  let open Crypto in
  let open Or_error.Let_syntax in
  let c_i, h_i = (initial_chain_key |> Key.shared_of_bytes, initial_chain_hash) in
  (* 3: H_i := HASH(H_i || S_r^{pub}) *)
  let%bind h_i = Hash_blake2s.hash2 h_i s_r_public in
  (* 5: C_i := KDF_1(C_i, E_i^{pub}) *)
  let c_i = Kdf.kdf_1 ~key:c_i (e_i.public) in
  let msg_ephemeral = e_i.public in
  (* 7: H_i := HASH(H_i || msg_ephemeral) *)
  let%bind h_i = Hash_blake2s.hash2 h_i msg_ephemeral in
  (* 8: (C_i, \kappa) := KDF_2(C_i, DH(E_i^{priv}, S_r^{pub})) *)
  let%bind ephemeral_shared =
    Ecdh.dh ~secret:e_i.secret ~public:s_r_public
  in
  let c_i, kappa = Kdf.kdf_2 ~key:c_i (Key.shared_to_bytes ephemeral_shared) in
  (* 9: msg.static = AEAD(\kappa, 0, S_i^{pub}, H_i) *)
  let%bind msg_static_signed =
    Aead.encrypt ~key:kappa ~counter:(Int64.of_int 0) ~message:s_i.public
      ~auth_text:h_i
  in
  (* 10: H_i = HASH(H_i || msg.static) *)
  let%bind h_i = Hash_blake2s.hash2 h_i msg_static_signed in
  (* 11: (C_i, \kappa) := KDF_2(C_i, DH(S_i^{priv}, S_r^{pub})) *)
  let%bind static_shared = Ecdh.dh ~secret:s_i.secret ~public:s_r_public in
  let c_i, kappa = Kdf.kdf_2 ~key:c_i (Key.shared_to_bytes static_shared) in
  (* 12: msg.timestamp = AEAD(\kappa, 0, TIMESTAMP(), H_i) *)
  let%bind msg_timestamp_signed =
    Aead.encrypt ~key:kappa ~counter:(Int64.of_int 0) ~message:timestamp
      ~auth_text:h_i
  in
  (* 13: H_i := HASH(H_i || msg.timestamp) *)
  let%map h_i = Hash_blake2s.hash2 h_i msg_timestamp_signed in
  let packet =
    first_message_of_fields ~msg_sender ~msg_ephemeral ~msg_static_signed
      ~msg_timestamp_signed
  in
  ((c_i, h_i), packet)
;;

(*let second_message ?q ~(incoming_packet : bytes) ~(msg_receiver : bytes)
    ~(e_r : Crypto.Key.keypair) ~(s_r : Crypto.Key.keypair)
    ~(s_i_public : Crypto.Key.public_key) :
    ((Crypto.Key.shared_key * bytes) * bytes) Or_error.t =
  let open Crypto in
  let open Or_error.Let_syntax in
  let c_r, h_r = (initial_chain_key, initial_chain_hash) in
  (* TODO: validate incoming packet ?? ?? ? ?*)
  assert (Bytes.length incoming_packet = 148) ;
  let _ = s_r in
  (* TODO: scrape ephemeral pubkey and sender out of packet *)
  let e_i = failwith "unimplemented" in
  let msg_sender = failwith "unimplemented" in
  (* 2: KDF_1(C_r, E_r^{pub})*)
  let c_r = Kdf.kdf_1 ~key:c_r e_r.public in
  let msg_ephemeral = e_r.public in
  (* 4: H_r := HASH(H_r || msg_ephemeral) *)
  let%bind h_r = Hash_blake2s.hash2 h_r msg_ephemeral in
  (* 5: C_r := KDF_1(C_r, DH(E_r^{priv}, E_i^{pub})) *)
  let%bind ephemeral_shared = Ecdh.dh ~secret:e_r.secret ~public:e_i in
  let c_r = Kdf.kdf_1 ~key:c_r ephemeral_shared in
  (* 5: C_r := KDF_1(C_r, DH(E_r^{priv}, S_i^{pub})) *)
  let%bind static_shared = Ecdh.dh ~secret:e_r.secret ~public:s_i_public in
  let c_r = Kdf.kdf_1 ~key:c_r static_shared in
  (* 7: (C_r, \tau, \kappa) := KDF_3(C_r, Q)*)
  let q = Option.value q ~default:(Bytes.make 32 '\x00') in
  let c_r, tau, kappa = Kdf.kdf_3 ~key:c_r q in
  (* 8: H_r := HASH(H_r || \tau) *)
  let%bind h_r = Hash_blake2s.hash2 h_r tau in
  (* 9: msg_empty = AEAD(\kappa, 0, \epsilon, H_r) *)
  let%bind msg_empty =
    Aead.encrypt ~key:kappa ~counter:(Int64.of_int 0)
      ~message:(Bytes.create 0) ~auth_text:h_r
  in
  (* 10: H_r := HASH(H_r || msg_empty) *)
  let%map h_r = Hash_blake2s.hash2 h_r msg_empty in
  let packet =
    second_message_of_fields ~msg_sender ~msg_receiver ~msg_ephemeral
      ~msg_empty
  in
  ((c_r, h_r), packet)
*)
let%expect_test "test-handshake-no-macs" =
  Crypto.Initialize.init () |> Or_error.ok_exn ;
  let e_r_public =
    Bytes.of_string
      "\xd1\x6d\xc1\x99\xb4\xef\xb3\xe0\x95\xc9\x66\x71\x04\xb8\xcf\x7d\x0c\x61\x17\xf5\x76\x35\x1b\x98\x86\xed\x20\x2e\xcc\x69\xfc\x10"
  in
  let e_r_private =
    Bytes.of_string
      "\x1d\x31\x97\x5c\x70\xad\xed\xd4\x34\xec\x3c\xe3\x86\xb1\xac\x82\xf4\x1a\xce\x52\xd9\x54\xd1\xba\x7b\xf7\xb1\x87\xbf\x3b\xb6\x59"
    |> Crypto.Key.secret_of_bytes
  in
  let _e_r = Crypto.Key.{secret= e_r_private; public= e_r_public} in
  let s_r_public =
    Bytes.of_string
      "\x27\x3e\x84\x40\x9a\x8f\x3f\x05\x43\xbb\xa9\xba\x51\x30\x06\x0e\x54\x41\x99\x77\xdc\xfe\xba\xbb\x7c\x87\x4b\x7e\xb1\x46\xf4\x73"
  in
  let s_r_private =
    Bytes.of_string
      "\x8b\x87\x15\xed\xfb\xa3\x0a\x08\x51\x39\xee\xba\x59\x66\x32\x45\x07\x18\x74\x74\xbe\x24\x12\x83\x8c\x2b\x07\x01\x65\x4b\x72\x03"
    |> Crypto.Key.secret_of_bytes
  in
  let _s_r = Crypto.Key.{secret= s_r_private; public= s_r_public} in
  let e_i_public =
    Bytes.of_string
      "\xeb\x71\x6c\x9c\xdb\x35\x67\xd1\xdf\xc2\xf4\x8f\xeb\xbb\xbd\x05\x9d\x8a\xda\x71\x50\xa9\xa4\x60\x28\x0b\xac\x09\xc1\x2c\xbb\x08"
  in
  let e_i_private =
    Bytes.of_string
      "\x30\x9b\xd4\x97\x6f\x21\x40\xd0\x6e\x3d\xff\x2b\x6c\x54\x33\xdc\x25\x12\xcd\x0e\x95\x92\x48\x14\x14\x67\x45\x6b\xa6\x95\x71\xf4"
    |> Crypto.Key.secret_of_bytes
  in
  let e_i = Crypto.Key.{secret= e_i_private; public= e_i_public} in
  let s_i_public =
    Bytes.of_string
      "\x1f\xfd\x47\xe6\x3d\x4b\xaa\xe9\x4a\x7e\x36\x47\x41\x81\xa3\x3f\xe2\x6f\x53\xc5\x8e\x9c\xfa\x4f\x15\xcc\xc9\xce\x54\x89\x9c\x5d"
  in
  let s_i_private =
    Bytes.of_string
      "\x43\xb7\x1a\xd5\x21\x8e\xb2\x37\x1d\x2b\x4a\xce\x14\x5c\x6f\xe9\x6a\xbb\x68\x4b\xc8\x2c\x9b\x5b\xd1\x0f\x28\xd2\x9f\x52\xcd\xca"
    |> Crypto.Key.secret_of_bytes
  in
  let s_i = Crypto.Key.{secret= s_i_private; public= s_i_public} in
  let timestamp =
    Bytes.of_string "\x40\x00\x00\x00\x5d\x60\x01\x88\x27\x13\x75\x69"
  in
  let msg_sender = Bytes.of_string "\x00\x64\x00\x00" in
  let _msg_receiver = Bytes.of_string "lmao" in
  ( match first_message ~timestamp ~msg_sender ~e_i ~s_i ~s_r_public with
  | Ok ((c_i, h_i), packet) -> (
      let packet_without_macs = Bytes.init 116 ~f:(Bytes.get packet) in
      print_s
        [%message
          (bytes_to_hex (Crypto.Key.shared_to_bytes c_i) : string)
          (bytes_to_hex h_i : string)
          (bytes_to_hex packet_without_macs : string)] ;
      (* CR crichoux:
      match
        second_message ~incoming_packet:packet ~msg_receiver ~e_r ~s_r
          ~s_i_public ?q:None
      with
      | Ok ((c_r, h_r), packet2) ->
          let packet2_without_macs = Bytes.init 64 ~f:(Bytes.get packet2) in
          print_s
            [%message
              (bytes_to_hex c_r : string)
                (bytes_to_hex h_r : string)
                (bytes_to_hex packet2_without_macs : string)]
      | Error e -> print_s [%message (e : Error.t)] )*)
      ())
  | Error e -> print_s [%message (e : Error.t)] ) ;
  [%expect
    {|
    (("bytes_to_hex c_i"
       "5b09 a279 7518 960d 0709 a59a 1c9d c9c9\
      \n7973 572c 3b8a fe5a 908f f177 5fcb 470a\
      \n")
     ("bytes_to_hex h_i"
       "eb99 3d46 2442 5bf9 5b47 fabe a17f 6889\
      \na571 e589 0a7a c7cc dff3 92cf 5630 0e2a\
      \n")
     ("bytes_to_hex packet_without_macs"
       "0100 0000 0064 0000 eb71 6c9c db35 67d1\
      \ndfc2 f48f ebbb bd05 9d8a da71 50a9 a460\
      \n280b ac09 c12c bb08 dac4 58de e7d9 1eee\
      \nd37d eb3b e063 3db7 0082 757c 1852 aea0\
      \n6902 fff2 f45a a952 1822 8b6f c957 5ef7\
      \n2773 d12f 878c d0ad 80c9 457b a2bc d705\
      \n0201 c309 f1e5 7d7e fbb2 ba8c afbe 56b3\
      \nde7d 4aea                              \
      \n"))
   |}]
