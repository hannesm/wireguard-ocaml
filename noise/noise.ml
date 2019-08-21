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

let label_mac1 = Bytes.of_string "mac1----"
let label_cookie = Bytes.of_string "cookie--"

(* CR crichoux: add tests here, verify all strings *)
let timestamp () =
  let since_epoch = Time_ns.now () |> Time_ns.to_span_since_epoch in
  let seconds = Time_ns.Span.to_int63_seconds_round_down_exn since_epoch in
  let ns =
    Time_ns.Span.(since_epoch - of_int63_seconds seconds)
    |> Time_ns.Span.to_int_ns
    |> Int32.of_int_exn
  in
  let buf = Bytes.create 12 in
  Ocplib_endian.EndianBytes.BigEndian.set_int64 buf 0 (Int63.to_int64 seconds);
  Ocplib_endian.EndianBytes.BigEndian.set_int32 buf 8 ns;
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
      ~(s_r : Nacl_crypto.Key.public Nacl_crypto.Key.key)
      ~(s_i : Nacl_crypto.Key.keypair)
  =
  let open Nacl_crypto in
  let open Or_error.Let_syntax in
  let msg_type_and_reserved = Bytes.of_string "\x01\x00\x00\x00" in
  (* CR crichoux: consider memoizing the next 3 lines? *)
  let%bind c_i = Hash_blake2s.hash Misc.construction in
  let%bind h_i = Hash_blake2s.hash2 c_i Misc.identifier in
  let%bind h_i = Hash_blake2s.hash2 h_i s_r in
  let%bind e_i = Ecdh.generate () in
  let c_i = Kdf.kdf_1 ~key:c_i e_i.public in
  let msg_ephemeral = e_i.public in
  let%bind h_i = Hash_blake2s.hash2 h_i msg_ephemeral in
  let%bind ephemeral_shared = Ecdh.dh ~secret:e_i.secret ~public:s_r in
  let c_i, kappa = Kdf.kdf_2 ~key:c_i ephemeral_shared in
  let%bind msg_static_signed =
    Aead.encrypt ~key:kappa ~counter:(Int64.of_int 0) ~message:s_i.public ~auth_text:h_i
  in
  let%bind h_i = Hash_blake2s.hash2 h_i msg_static_signed in
  let%bind static_shared = Ecdh.dh ~secret:s_i.secret ~public:s_r in
  let _c_i, kappa = Kdf.kdf_2 ~key:c_i static_shared in
  let%bind msg_timestamp_signed =
    Aead.encrypt
      ~key:kappa
      ~counter:(Int64.of_int 0)
      ~message:(Misc.timestamp ())
      ~auth_text:h_i
  in
  let%map _h_i = Hash_blake2s.hash2 h_i msg_timestamp_signed in
  let message =
    first_message_of_fields
      ~msg_type_and_reserved
      ~msg_sender
      ~msg_ephemeral
      ~msg_static_signed
      ~msg_timestamp_signed
  in
  message
;;
