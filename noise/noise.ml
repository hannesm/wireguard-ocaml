open Core

(* let construction = Bytes.of_string "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
   let identifier = Bytes.of_string "WireGuard v1 zx2c4 Jason@zx2c4.com"*)

(* initiator.chaining_key = HASH(CONSTRUCTION)*)
let initial_chain_key =
  Bytes.of_string
    "\x60\xe2\x6d\xae\xf3\x27\xef\xc0\x2e\xc3\x35\xe2\xa0\x25\xd2\xd0\x16\xeb\x42\x06\xf8\x72\x77\xf5\x2d\x38\xd1\x98\x8b\x78\xcd\x36"
;;

(* initiator.chaining_hash = HASH(initiator.chaining_key || IDENTIFIER) *)
let initial_chain_hash =
  Bytes.of_string
    "\x22\x11\xb3\x61\x08\x1a\xc5\x66\x69\x12\x43\xdb\x45\x8a\xd5\x32\x2d\x9c\x6c\x66\x22\x93\xe8\xb7\x0e\xe1\x9c\x65\xba\x07\x9e\xf3'"
;;

let _label_mac1 = Bytes.of_string "mac1----"
let _label_cookie = Bytes.of_string "cookie--"

(* CR crichoux: add tests here, verify all strings *)
let timestamp () =
  let since_epoch = Time_ns.now () |> Time_ns.to_span_since_epoch in
  let ns_since_epoch = (Time_ns.Span.to_int63_ns since_epoch) |> Int63.to_int64 in
  let seconds, ns =
    let thousand = Int64.of_int 1000 in
    Int64.(ns_since_epoch / thousand, ns_since_epoch % thousand)
  in
  let buf = Bytes.create 12 in
  EndianBytes.BigEndian.set_int64 buf 0 seconds;
  EndianBytes.BigEndian.set_int32 buf 8 (Int64.to_int32_trunc ns);
  buf
;;

let _add_macs ~message ~message_length =
  assert (Bytes.length message = message_length + 32);
  failwith "unimplemented"
;;

let first_message_of_fields
      ~msg_type_and_reserved
      ~msg_sender
      ~msg_ephemeral
      ~msg_static_signed
      ~msg_timestamp_signed
  =
  assert (Bytes.length msg_type_and_reserved = 4);
  assert (Bytes.length msg_sender = 4);
  assert (Bytes.length msg_ephemeral = 32);
  assert (Bytes.length msg_static_signed = 48);
  assert (Bytes.length msg_timestamp_signed = 28);
  let buf = Bytes.create 148 in
  Bytes.blit ~src:msg_type_and_reserved ~src_pos:0 ~dst:buf ~dst_pos:0 ~len:4;
  Bytes.blit ~src:msg_sender ~src_pos:0 ~dst:buf ~dst_pos:4 ~len:4;
  Bytes.blit ~src:msg_ephemeral ~src_pos:0 ~dst:buf ~dst_pos:8 ~len:32;
  Bytes.blit ~src:msg_static_signed ~src_pos:0 ~dst:buf ~dst_pos:40 ~len:48;
  Bytes.blit ~src:msg_timestamp_signed ~src_pos:0 ~dst:buf ~dst_pos:88 ~len:28;
  buf
;;

let first_message
      ~(msg_sender : bytes)
      ~(e_i : Nacl_crypto.Key.keypair)
      ~(s_r : Nacl_crypto.Key.public Nacl_crypto.Key.key)
      ~(s_i : Nacl_crypto.Key.keypair)
  =
  let open Nacl_crypto in
  let open Or_error.Let_syntax in
  let msg_type_and_reserved = Bytes.of_string "\x01\x00\x00\x00" in
  let c_i, h_i = initial_chain_key, initial_chain_hash in
  (* 3: H_i := HASH(H_i || S_r^{pub}) *)
  let%bind h_i = Hash_blake2s.hash2 h_i s_r in
  (* 5: C_i := KDF_1(C_i, E_i^{pub}) *)
  let c_i = Kdf.kdf_1 ~key:c_i e_i.public in
  let msg_ephemeral = e_i.public in
  (* 7: H_i := HASH(H_i || msg_ephemeral) *)
  let%bind h_i = Hash_blake2s.hash2 h_i msg_ephemeral in
  (* 8: (C_i, \kappa) := KDF_2(C_i, DH(E_i^{priv}, S_r^{pub})) *)
  let%bind ephemeral_shared = Ecdh.dh ~secret:e_i.secret ~public:s_r in
  let c_i, kappa = Kdf.kdf_2 ~key:c_i ephemeral_shared in
  (* 9: msg.static = AEAD(\kappa, 0, S_i^{pub}, H_i) *)
  let%bind msg_static_signed =
    Aead.encrypt ~key:kappa ~counter:(Int64.of_int 0) ~message:s_i.public ~auth_text:h_i
  in
  (* 10: H_i = HASH(H_i || msg.static) *)
  let%bind h_i = Hash_blake2s.hash2 h_i msg_static_signed in
  (* 11: (C_i, \kappa) := KDF_2(C_i, DH(S_i^{priv}, S_r^{pub})) *)
  let%bind static_shared = Ecdh.dh ~secret:s_i.secret ~public:s_r in
  let c_i, kappa = Kdf.kdf_2 ~key:c_i static_shared in
  (* 12: msg.timestamp = AEAD(\kappa, 0, TIMESTAMP(), H_i) *)
  let%bind msg_timestamp_signed =
    Aead.encrypt
      ~key:kappa
      ~counter:(Int64.of_int 0)
      ~message:(timestamp ())
      ~auth_text:h_i
  in
  (* 13: H_i := HASH(H_i || msg.timestamp) *)
  let%map h_i = Hash_blake2s.hash2 h_i msg_timestamp_signed in
  let packet =
    first_message_of_fields
      ~msg_type_and_reserved
      ~msg_sender
      ~msg_ephemeral
      ~msg_static_signed
      ~msg_timestamp_signed
  in
  (c_i, h_i), packet
;;

let%expect_test "test-handshake" =
  Nacl_crypto.Initialize.init () |> Or_error.ok_exn;
  let peer_static_public = Bytes.of_string "\x7d\x6a\xc5\x60\x56\xdc\x48\xc6\x7c\x4a\x26\xdb\xd2\xfb\xce\xdc\x4c\x6c\x4c\x06\xbf\xe9\x1e\x06\x22\x0f\xde\xec\xf9\xc3\x5c\x2f" in
  let ephemeral_private = Bytes.of_string "\x89\x68\x18\xcf\x9c\x83\xd3\xc1\x34\x6d\x77\x8c\x13\x68\x5e\x06\x1c\xd8\xc6\x4a\xc9\x52\x0b\x0a\x2e\xab\x6b\xe6\x34\xfe\xd9\xa4" in
  let ephemeral_public = Bytes.of_string "\xe8\xf2\x3c\xd6\x40\x83\x41\xe7\xbb\xdd\x8a\x05\x19\xea\xc4\xe8\xc3\xd9\x4f\xb0\x2a\x8c\x72\xec\xd9\xbd\x06\x97\x78\x45\x3f\x7d" in
  let e_i = Nacl_crypto.Key.{secret=ephemeral_private; public=ephemeral_public} in
  let msg_sender = Bytes.of_string "\x00\x64\x00\x00" in
  let own_static_public = Bytes.of_string "\x50\x26\x84\x96\x13\x61\x80\x43\x41\x99\x21\xfb\x82\x0a\x60\x4b\x6f\x82\x89\xdd\xe1\x93\x52\x67\xbb\xb8\xa9\xd6\xba\xd4\x15\x49" in
  let own_static_private = Bytes.of_string "\xeb\xcc\xa5\x2a\x1e\xa5\x56\x1c\xb6\xd2\xaa\xd1\xe8\xdf\x20\x18\x36\xef\x67\xdd\x1e\x5a\xb4\x73\x68\xc3\x34\x6b\x86\xda\x81\xa1" in
  let s_i = Nacl_crypto.Key.{secret=own_static_private; public=own_static_public} in
  let (c_i, h_i), packet = first_message ~msg_sender ~e_i ~s_i ~s_r:peer_static_public |> Or_error.ok_exn in
  print_s [%message (Bytes.to_string c_i:string) (Bytes.to_string h_i:string) (Bytes.to_string packet:string )];
  [%expect {|
    (("Bytes.to_string c_i"
      "\003\215\006\184\149\004\196\151\212\012\166\198\239\180K\255t\210b\163E\201![\230\242\177\029\129Z*\189")
    [b, 3e, cc, 83, 5c, 61, 46, 66, 75, df, 83, f0, ef, 4b, 90, 59, 2d, c5, 99, dc, e6, 80, ff, 83, 3d, 2c, 93, 17, c1, b5, 7b, 14]
    [1, 0, 0, 0, 0, 64, 0, 0, e8, f2, 3c, d6, 40, 83, 41, e7, bb, dd, 8a, 5, 19, ea, c4, e8, c3, d9, 4f, b0, 2a, 8c, 72, ec, d9, bd, 6, 97, 78, 45, 3f, 7d, fe, f6, 5c, 4d, cd, a3, 65, e2, ea, 54, ee, a, a4, 7f, 3e, 53, f8, 75, ac, 13, 30, 7c, f3, 48, dc, e0, d4, 4d, 5d, e4, 21, 36, f7, 78, e8, ef, af, b4, 7f, 95, db, 27, b, 6, ea, 8a, 63, 18, 3b, ba, a, d0, 57, 2c, fd, 25, c7, 85, 5c, f2, f5, f9, 63, 7c, c5, e5, 61, 1e, 48, 11, e8, 57, 4e, af, b2, 26, f3, b8, 26, 37, c, ea, a4, 3f, e1, 83, 51, 75, 31, 5c, 23, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
   |}]
;;
