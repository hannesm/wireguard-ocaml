open Core
open Stdint
open Or_error.Let_syntax
open Crypto

(* CR crichoux: worry about clearing and managing memory later. *)

let empty_bytes () = Bytes.create 0

(* various nothing-up-my-sleeve constants *)
let _noise_construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
let _wg_identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"
let handshake_initiation_rate : Time_ns.Span.t = Time_ns.Span.of_int_ms 20

(* initiator.chaining_key = HASH(CONSTRUCTION)*)
(* CR crichoux: put these in an init function *)
let initial_chain_key =
  Bytes.of_string
    "\x60\xe2\x6d\xae\xf3\x27\xef\xc0\x2e\xc3\x35\xe2\xa0\x25\xd2\xd0\x16\xeb\x42\x06\xf8\x72\x77\xf5\x2d\x38\xd1\x98\x8b\x78\xcd\x36"

(* initiator.chaining_hash = HASH(initiator.chaining_key || IDENTIFIER) *)
let initial_chain_hash =
  Bytes.of_string
    "\x22\x11\xb3\x61\x08\x1a\xc5\x66\x69\x12\x43\xdb\x45\x8a\xd5\x32\x2d\x9c\x6c\x66\x22\x93\xe8\xb7\x0e\xe1\x9c\x65\xba\x07\x9e\xf3"

(* optionally pass in constants for values that should be generated *)
(* just for testing! *)
let create_message_initiation ?timestamp ?local_ephemeral
    ~(local_static_public : Public.key) (handshake : Handshake.t) :
    Message.handshake_initiation Or_error.t =
  (* CR crichoux: worry about this soon/later device.staticIdentity.RLock()
     defer device.staticIdentity.RUnlock() *)
  (* CR crichoux: worry about this soon handshake.mutex.Lock() defer
     handshake.mutex.Unlock() *)
  let ret = Message.new_handshake_initiation () in
  let%bind () =
    Result.ok_if_true
      (not
         (Crypto.is_zero (Handshake.get_t_precomputed_static_static handshake)))
      ~error:(Error.of_string "handshake precomputed static is zero") in
  Handshake.blit_t_hash handshake initial_chain_hash ;
  Handshake.blit_t_chain_key handshake initial_chain_key ;
  (* create ephemeral key *)
  let%bind () =
    let%map local_ephemeral =
      match local_ephemeral with Some le -> Ok le | None -> generate () in
    Handshake.blit_t_ephemeral_keypair handshake local_ephemeral in
  (* assign index *)
  (let local_index : Cstruct.uint32 = Int32.of_int 3 in
   Handshake.set_t_local_index handshake local_index ;
   Message.set_handshake_initiation_sender ret local_index) ;
  (* CR crichoux: TODO device.indexTable.Delete(handshake.localIndex)
     handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer,
     handshake) *)
  let%bind () =
    Handshake.mix_hash handshake (Handshake.get_t_remote_static handshake)
  in
  let ephemeral = Handshake.get_t_local_ephemeral_public handshake in
  Handshake.mix_key handshake ephemeral ;
  Message.blit_handshake_initiation_ephemeral ret ephemeral ;
  let%bind () = Handshake.mix_hash handshake ephemeral in
  (* encrypt static key *)
  let%bind ephemeral_shared =
    let local_eph_secret = Handshake.get_t_local_ephemeral_private handshake in
    let remote_stat_public = Handshake.get_t_remote_static handshake in
    dh
      ~secret:(Secret.of_bytes local_eph_secret)
      ~public:(Public.of_bytes remote_stat_public) in
  let kappa = Handshake.mix_key2 handshake (Shared.to_bytes ephemeral_shared) in
  let%bind signed_static =
    aead_encrypt ~key:kappa ~counter:(Int64.of_int 0)
      ~message:(Public.to_bytes local_static_public)
      ~auth_text:(Handshake.get_t_hash handshake) in
  let%bind () = Handshake.mix_hash handshake signed_static in
  Message.blit_handshake_initiation_signed_static ret signed_static ;
  (* encrypt timestamp *)
  let timestamp =
    (match timestamp with Some ts -> ts | None -> Tai64n.now ())
    |> Tai64n.to_bytes in
  let kappa =
    Handshake.mix_key2 handshake
      (Handshake.get_t_precomputed_static_static handshake) in
  Handshake.blit_t_precomputed_static_static handshake (Shared.to_bytes kappa) ;
  let%bind signed_timestamp =
    aead_encrypt ~key:kappa ~counter:(Int64.of_int 0) ~message:timestamp
      ~auth_text:(Handshake.get_t_hash handshake) in
  let%map () = Handshake.mix_hash handshake signed_timestamp in
  Message.blit_handshake_initiation_signed_timestamp ret signed_timestamp ;
  Handshake.set_t_state handshake Handshake.Handshake_initiation_created ;
  ret

let mix_key ~chain_key bytes : unit =
  let c_i = kdf_1 ~key:(Shared.of_bytes chain_key) bytes in
  Bytes.blit ~src:(Shared.to_bytes c_i) ~src_pos:0 ~dst:chain_key ~dst_pos:0
    ~len:32

let mix_key2 ~chain_key bytes : Shared.key =
  let c_i, kappa = kdf_2 ~key:(Shared.of_bytes chain_key) bytes in
  Bytes.blit ~src:(Shared.to_bytes c_i) ~src_pos:0 ~dst:chain_key ~dst_pos:0
    ~len:32 ;
  kappa

let mix_hash ~hash bytes : unit Or_error.t =
  let%map res = hash2 hash bytes in
  Bytes.blit ~src:res ~src_pos:0 ~dst:hash ~dst_pos:0 ~len:32

(* CR crichoux: dummy type, will fill out better later *)
type peer = {handshake: Handshake.t; keypairs: Keypair.ts ref}

(* peer arg for testing only! should not be passed in in prod. *)
let consume_message_initiation ?peer ~(msg : Message.handshake_initiation)
    ~(local_static : keypair) : peer Or_error.t =
  let hash = Bytes.copy initial_chain_hash in
  let chain_key = Bytes.copy initial_chain_key in
  let%bind () = mix_hash ~hash (Public.to_bytes local_static.public) in
  let ephemeral = Message.get_handshake_initiation_ephemeral msg in
  let%bind () = mix_hash ~hash ephemeral in
  mix_key ~chain_key ephemeral ;
  (* CR crichoux: take care of this device.staticIdentity.RLock() defer
     device.staticIdentity.RUnlock() *)

  (* decrypt static key *)
  let%bind ephemeral_shared =
    dh ~secret:local_static.secret ~public:(Public.of_bytes ephemeral) in
  let kappa = mix_key2 ~chain_key (Shared.to_bytes ephemeral_shared) in
  let signed_static = Message.get_handshake_initiation_signed_static msg in
  let%bind peer_pk =
    aead_decrypt ~key:kappa ~counter:(Int64.of_int 0) ~ciphertext:signed_static
      ~auth_text:hash in
  let%bind () = mix_hash ~hash signed_static in
  (* lookup peer *)
  let peer =
    match peer with Some peer -> peer | None -> failwith "unimplemented" in
  let handshake = peer.handshake in
  (* CR crichoux: change this to something sensical.... *)
  assert (Bytes.equal peer_pk (Handshake.get_t_remote_static handshake)) ;
  let pss = Handshake.get_t_precomputed_static_static handshake in
  (* CR crichoux: make this a function *)
  let%bind () =
    Result.ok_if_true
      (not (Crypto.is_zero pss))
      ~error:(Error.of_string "handshake precomputed static is zero") in
  (* verify identity *)
  let kappa = mix_key2 ~chain_key pss in
  let signed_timestamp =
    Message.get_handshake_initiation_signed_timestamp msg in
  let%bind timestamp =
    aead_decrypt ~key:kappa ~counter:(Int64.of_int 0)
      ~ciphertext:signed_timestamp ~auth_text:hash in
  let%bind () = mix_hash ~hash signed_timestamp in
  (* CR crichoux: take care of this handshake.mutex.RLock() *)

  (* protect against replays, floods *)
  let%map () =
    let last_timestamp = Handshake.get_t_last_timestamp handshake in
    let ok =
      Tai64n.after (Tai64n.of_bytes timestamp) (Tai64n.of_bytes last_timestamp)
    in
    (* CR crichoux: figure this one out *)
    let ok =
      let last_init_consump =
        Handshake.get_t_last_initiation_consumption handshake in
      ok
      && Time_ns.Span.(
           Tai64n.diff (Tai64n.now ()) (Tai64n.of_bytes last_init_consump)
           > handshake_initiation_rate) in
    Result.ok_if_true ok
      ~error:(Error.of_string "insufficient time since last initiation") in
  Handshake.blit_t_hash handshake hash ;
  Handshake.blit_t_chain_key handshake chain_key ;
  let sender = Message.get_handshake_initiation_sender msg in
  Handshake.set_t_remote_index handshake sender ;
  Handshake.blit_t_remote_ephemeral handshake ephemeral ;
  Handshake.blit_t_last_timestamp handshake timestamp ;
  Handshake.blit_t_last_initiation_consumption handshake
    (Tai64n.now () |> Tai64n.to_bytes) ;
  Handshake.set_t_state handshake Handshake.Handshake_initiation_consumed ;
  Crypto.zero_buffer hash ;
  Crypto.zero_buffer chain_key ;
  {handshake; keypairs= ref (Keypair.create_empty_ts ())}

let int_list_to_bytes int_list =
  let char_list = List.map ~f:char_of_int int_list in
  Bytes.of_char_list char_list

let pretty_print_bytes bytes = bytes |> Cstruct.of_bytes |> Cstruct.hexdump

let create_message_response ?local_ephemeral peer :
    Message.handshake_response Or_error.t =
  let handshake = peer.handshake in
  let create_message_response_ () =
    let ret = Message.new_handshake_response () in
    let sender = Handshake.get_t_local_index handshake in
    let receiver = Handshake.get_t_remote_index handshake in
    Message.set_handshake_response_sender ret sender ;
    Message.set_handshake_response_receiver ret receiver ;
    let%bind local_ephemeral =
      match local_ephemeral with Some le -> Ok le | None -> generate () in
    Handshake.blit_t_ephemeral_keypair handshake local_ephemeral ;
    let ephemeral = Public.to_bytes local_ephemeral.public in
    let%bind () = Handshake.mix_hash handshake ephemeral in
    Handshake.mix_key handshake ephemeral ;
    Message.blit_handshake_response_ephemeral ret ephemeral ;
    let%bind ephemeral_shared =
      let remote_eph_public = Handshake.get_t_remote_ephemeral handshake in
      dh ~secret:local_ephemeral.secret
        ~public:(Public.of_bytes remote_eph_public) in
    Handshake.mix_key handshake (Shared.to_bytes ephemeral_shared) ;
    let%bind static_shared =
      let remote_stat_public = Handshake.get_t_remote_static handshake in
      dh ~secret:local_ephemeral.secret
        ~public:(Public.of_bytes remote_stat_public) in
    Handshake.mix_key handshake (Shared.to_bytes static_shared) ;
    let tau, kappa =
      Handshake.mix_key3 handshake (Handshake.get_t_preshared_key handshake)
    in
    let%bind () = Handshake.mix_hash handshake (Shared.to_bytes tau) in
    let%bind empty =
      aead_encrypt ~key:kappa ~counter:(Int64.of_int 0)
        ~message:(empty_bytes ())
        ~auth_text:(Handshake.get_t_hash handshake) in
    Message.blit_handshake_response_signed_empty ret empty ;
    let%map () = Handshake.mix_hash handshake empty in
    Handshake.set_t_state handshake Handshake.Handshake_response_created ;
    ret in
  match Handshake.get_t_state handshake with
  | Handshake.Handshake_initiation_consumed -> create_message_response_ ()
  | state ->
      Or_error.error_s
        [%message
          "handshake is in the wrong state to call create_message_response!"
            (state : Handshake.noise_state)]

(* in real implementation, lookup handshake by receiver id *)
(* in real implementation get local_static from device *)
let consume_message_response ?handshake ?local_static
    (msg : Message.handshake_response) : peer Or_error.t =
  let%bind handshake =
    match handshake with
    | Some handshake -> Ok handshake
    | None -> Or_error.error_string "unimplemented handshake lookup" in
  let%bind () =
    match Handshake.get_t_state handshake with
    | Handshake.Handshake_initiation_created -> Ok ()
    | state ->
        Or_error.error_s
          [%message
            "handshake is in the wrong state to call consume_message_response!"
              (state : Handshake.noise_state)] in
  let ephemeral = Message.get_handshake_response_ephemeral msg in
  let%bind () = Handshake.mix_hash handshake ephemeral in
  Handshake.mix_key handshake ephemeral ;
  let local_ephemeral_secret =
    Handshake.get_t_local_ephemeral_private handshake in
  let%bind ephemeral_shared =
    dh
      ~secret:(Secret.of_bytes local_ephemeral_secret)
      ~public:(Public.of_bytes ephemeral) in
  Handshake.mix_key handshake (Shared.to_bytes ephemeral_shared) ;
  Shared.set_zero ephemeral_shared ;
  let%bind local_static =
    match local_static with
    | Some local_static -> Ok local_static
    | None -> Or_error.error_string "unimplemented handshake lookup" in
  let%bind static_shared =
    dh ~secret:local_static.secret ~public:(Public.of_bytes ephemeral) in
  Handshake.mix_key handshake (Shared.to_bytes static_shared) ;
  Shared.set_zero static_shared ;
  let tau, kappa =
    Handshake.mix_key3 handshake (Handshake.get_t_preshared_key handshake)
  in
  let%bind () = Handshake.mix_hash handshake (Shared.to_bytes tau) in
  let signed_empty = Message.get_handshake_response_signed_empty msg in
  let%bind _empty =
    aead_decrypt ~key:kappa ~counter:(Int64.of_int 0) ~ciphertext:signed_empty
      ~auth_text:(Handshake.get_t_hash handshake) in
  let%map () = Handshake.mix_hash handshake signed_empty in
  Handshake.set_t_state handshake Handshake.Handshake_response_consumed ;
  {handshake; keypairs= ref (Keypair.create_empty_ts ())}

let begin_symmetric_session peer : unit Or_error.t =
  let handshake = peer.handshake in
  let chain_key = Shared.of_bytes (Handshake.get_t_chain_key handshake) in
  let%map (send, receive), is_initiator =
    match Handshake.get_t_state handshake with
    | Handshake_response_consumed ->
        (Crypto.kdf_2 ~key:chain_key (empty_bytes ()), true) |> Or_error.return
    | Handshake_response_created ->
        Crypto.kdf_2 ~key:chain_key (empty_bytes ())
        |> fun (a, b) -> ((b, a), false) |> Or_error.return
    | _ -> Or_error.error_string "invalid state for keypair derivation" in
  Handshake.zero_t_chain_key handshake ;
  Handshake.zero_t_hash handshake ;
  Handshake.zero_t_local_ephemeral handshake ;
  Handshake.set_t_state handshake Handshake.Handshake_zeroed ;
  let open Keypair in
  let keypair =
    create_t ~send_nonce:Int64.zero ~send ~receive ~replay_filter:0
      ~is_initiator:(if is_initiator then 1 else 0)
      ~created:(Tai64n.now ())
      ~local_index:(Handshake.get_t_local_index handshake)
      ~remote_index:(Handshake.get_t_remote_index handshake) in
  (* CR crichoux: remap device index... what's that? *)
  (* device.indexTable.SwapIndexForKeypair(handshake.localIndex, keypair)
     handshake.localIndex = 0 *)
  let {current; previous= _; next} = !(peer.keypairs) in
  let keypairs =
    if is_initiator then
      let next, previous =
        match next with
        | Some _ ->
            (* device.delete_keypair current ; *)
            (None, next)
        | None -> (next, current) in
      let current = Some keypair in
      {current; next; previous}
    else
      { (* device.delete_keypair next ; device.delete_keypair previous ;*)
        current
      ; previous= None
      ; next= Some keypair } in
  peer.keypairs := keypairs

(* CR crichoux: what is this for again *)
(* CR crichoux: untested! *)
(* let received_with_keypair ~(peer : peer) recv_keypair : bool = (* CR
   crichoux: handle keypair mutex stuff from go? *) let keypairs =
   !(peer.keypairs) in match keypairs.next with | None -> false | Some
   next_pair -> if not (Keypair.equal_t next_pair recv_keypair) then false else
   let _old = keypairs.previous in let previous = keypairs.current in (*
   device.delete_keypair old ;*) let current = keypairs.next in let next = None
   in peer.keypairs := {current; previous; next} ; true *)

let test_key_pairs peer1 peer2 : unit Or_error.t =
  let%bind send1, receive1 =
    match !(peer1.keypairs).next with
    | Some n -> Ok (Keypair.get_t_send n, Keypair.get_t_receive n)
    | None -> Or_error.error_string "no next key for peer1" in
  let%bind send2, receive2 =
    match !(peer2.keypairs).current with
    | Some n -> Ok (Keypair.get_t_send n, Keypair.get_t_receive n)
    | None -> Or_error.error_string "no current key for peer2" in
  let auth_text = empty_bytes () in
  let m_1 = Bytes.of_string "wireguard test message 1" in
  let ctr_1 = Int64.of_int 13289420 in
  let%bind c_1 =
    Crypto.aead_encrypt ~key:send1 ~counter:ctr_1 ~message:m_1 ~auth_text in
  let%bind m_1_dec =
    Crypto.aead_decrypt ~key:receive2 ~counter:ctr_1 ~ciphertext:c_1 ~auth_text
  in
  let m_2 = Bytes.of_string "wireguard test message 2" in
  let ctr_2 = Int64.of_int 43290128 in
  let%bind c_2 =
    Crypto.aead_encrypt ~key:send2 ~counter:ctr_2 ~message:m_2 ~auth_text in
  let%bind m_2_dec =
    Crypto.aead_decrypt ~key:receive1 ~counter:ctr_2 ~ciphertext:c_2 ~auth_text
  in
  if Bytes.equal m_1 m_1_dec && Bytes.equal m_2 m_2_dec then Ok ()
  else Or_error.error_string "failed correct encryption and decryption..."

let%expect_test "test_handshake_against_go_constants" =
  Crypto.init () |> Or_error.ok_exn ;
  (* all constants from output of wireguard-go tests *)
  (* local and remote static keys *)
  let dev1_static_private =
    int_list_to_bytes
      [ 224; 114; 26; 212; 195; 244; 59; 190; 172; 168; 61; 43; 199; 150; 127
      ; 38; 231; 253; 83; 239; 77; 53; 17; 129; 247; 46; 198; 121; 147; 242; 95
      ; 99 ]
    |> Crypto.Secret.of_bytes in
  let dev1_static_public =
    int_list_to_bytes
      [ 164; 241; 106; 150; 20; 255; 195; 182; 223; 236; 37; 135; 126; 101; 187
      ; 255; 211; 191; 16; 19; 15; 134; 234; 31; 252; 52; 138; 62; 88; 14; 120
      ; 36 ]
    |> Crypto.Public.of_bytes in
  let dev2_static_private =
    int_list_to_bytes
      [ 56; 63; 223; 191; 65; 76; 161; 98; 187; 219; 126; 199; 86; 23; 147; 194
      ; 204; 57; 156; 82; 225; 132; 10; 140; 254; 102; 97; 25; 91; 249; 140
      ; 127 ]
    |> Crypto.Secret.of_bytes in
  let dev2_static_public =
    int_list_to_bytes
      [ 178; 147; 147; 105; 114; 57; 113; 157; 55; 78; 29; 91; 95; 80; 71; 23
      ; 132; 248; 26; 37; 211; 31; 233; 77; 185; 132; 60; 141; 237; 179; 140
      ; 53 ]
    |> Crypto.Public.of_bytes in
  (* local and remote ephemeral keys *)
  let dev1_ephemeral_private =
    int_list_to_bytes
      [ 224; 128; 105; 132; 216; 1; 207; 234; 117; 21; 175; 45; 37; 11; 107; 251
      ; 152; 90; 145; 131; 204; 95; 117; 155; 91; 5; 94; 149; 249; 4; 247; 70
      ]
    |> Crypto.Secret.of_bytes in
  let dev1_ephemeral_public =
    int_list_to_bytes
      [ 85; 135; 231; 208; 15; 35; 21; 225; 55; 108; 126; 159; 20; 213; 11; 46
      ; 95; 135; 236; 74; 31; 99; 68; 254; 82; 159; 148; 217; 233; 79; 83; 118
      ]
    |> Crypto.Public.of_bytes in
  let dev2_ephemeral_private =
    int_list_to_bytes
      [ 80; 9; 108; 30; 226; 174; 138; 236; 151; 228; 202; 108; 93; 98; 246; 194
      ; 113; 195; 125; 36; 126; 70; 193; 172; 144; 191; 209; 249; 221; 188; 199
      ; 98 ]
    |> Crypto.Secret.of_bytes in
  let dev2_ephemeral_public =
    int_list_to_bytes
      [ 15; 210; 28; 84; 230; 108; 56; 68; 19; 52; 180; 101; 114; 37; 13; 99
      ; 224; 79; 227; 122; 85; 100; 224; 195; 22; 64; 247; 160; 65; 149; 57; 49
      ]
    |> Crypto.Public.of_bytes in
  (* timestamp *)
  let timestamp =
    int_list_to_bytes [64; 0; 0; 0; 93; 102; 199; 171; 9; 0; 0; 0]
    |> Tai64n.of_bytes in
  let static_keypair1 =
    {secret= dev1_static_private; public= dev1_static_public} in
  let static_keypair2 =
    {secret= dev2_static_private; public= dev2_static_public} in
  let ephemeral_keypair1 =
    {secret= dev1_ephemeral_private; public= dev1_ephemeral_public} in
  let ephemeral_keypair2 =
    {secret= dev2_ephemeral_private; public= dev2_ephemeral_public} in
  let handshake1 : Handshake.t = Handshake.new_handshake () in
  let handshake2 : Handshake.t = Handshake.new_handshake () in
  Handshake.blit_t_remote_static handshake1
    (Public.to_bytes static_keypair2.public) ;
  Handshake.blit_t_remote_static handshake2
    (Public.to_bytes static_keypair1.public) ;
  let shared_static_static1 : bytes =
    Crypto.dh ~secret:static_keypair1.secret ~public:static_keypair2.public
    |> Or_error.ok_exn |> Shared.to_bytes in
  Handshake.blit_t_precomputed_static_static handshake1 shared_static_static1 ;
  let shared_static_static2 : bytes =
    Crypto.dh ~secret:static_keypair2.secret ~public:static_keypair1.public
    |> Or_error.ok_exn |> Shared.to_bytes in
  Handshake.blit_t_precomputed_static_static handshake2 shared_static_static2 ;
  (* set precomputed_static_static *)
  let handshake_initiation : Message.handshake_initiation =
    create_message_initiation ~local_ephemeral:ephemeral_keypair1 ~timestamp
      ~local_static_public:static_keypair1.public handshake1
    |> Or_error.ok_exn in
  Message.hexdump_handshake_initiation handshake_initiation ;
  let peer1 : peer =
    consume_message_initiation
    (* for testing only! should not be passed in in prod. *)
      ~peer:{handshake= handshake2; keypairs= ref (Keypair.create_empty_ts ())}
      ~msg:handshake_initiation ~local_static:static_keypair2
    |> Or_error.ok_exn in
  let handshake_response : Message.handshake_response =
    create_message_response ~local_ephemeral:ephemeral_keypair2 peer1
    |> Or_error.ok_exn in
  Message.hexdump_handshake_response handshake_response ;
  let peer2 : peer =
    consume_message_response ~handshake:handshake1
      ~local_static:static_keypair1 handshake_response
    |> Or_error.ok_exn in
  let chain_hash_1, chain_key_1 =
    (Handshake.get_t_hash handshake1, Handshake.get_t_chain_key handshake1)
  in
  let chain_hash_2, chain_key_2 =
    (Handshake.get_t_hash handshake2, Handshake.get_t_chain_key handshake2)
  in
  print_string "chain_hash_1\n" ;
  pretty_print_bytes chain_hash_1 ;
  print_string "chain_key_1\n" ;
  pretty_print_bytes chain_key_1 ;
  print_string "chain_hash_2\n" ;
  pretty_print_bytes chain_hash_2 ;
  print_string "chain_key_2\n" ;
  pretty_print_bytes chain_key_2 ;
  let () = begin_symmetric_session peer1 |> Or_error.ok_exn in
  let () = begin_symmetric_session peer2 |> Or_error.ok_exn in
  test_key_pairs peer1 peer2 |> Or_error.ok_exn ;
  [%expect
    {|
  handshake_initiation = {
    msg_type = 0x1
    sender = 0x3
    ephemeral = <buffer uint8_t[32] ephemeral>
  55 87 e7 d0 0f 23 15 e1  37 6c 7e 9f 14 d5 0b 2e
  5f 87 ec 4a 1f 63 44 fe  52 9f 94 d9 e9 4f 53 76

    signed_static = <buffer uint8_t[48] signed_static>
  e1 26 a3 99 20 6a ee 1a  a7 bc 39 a8 0b 4d 89 9c
  85 f7 df 4b 91 a3 fc 1b  71 5b c4 d8 cb 65 7b db
  86 51 42 4c 97 88 c4 e6  7a 1d e7 26 ed 7c 70 15

    signed_timestamp = <buffer uint8_t[28] signed_timestamp>
  3f e9 71 7f 93 7a f1 91  e0 62 fc a9 80 dc 9c d8
  20 c3 76 a5 11 80 f3 3e  a9 85 33 c5
    mac1 = <buffer uint8_t[32] mac1>
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00

    mac2 = <buffer uint8_t[32] mac2>
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00


  }
  handshake_response = {
    msg_type = 0x2
    sender = 0x0
    receiver = 0x3
    ephemeral = <buffer uint8_t[32] ephemeral>
  0f d2 1c 54 e6 6c 38 44  13 34 b4 65 72 25 0d 63
  e0 4f e3 7a 55 64 e0 c3  16 40 f7 a0 41 95 39 31

    signed_empty = <buffer uint8_t[16] signed_empty>
  8b 0e 1d 50 50 2e 9c b1  cb 45 53 6a c6 7b 05 b9

    mac1 = <buffer uint8_t[32] mac1>
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00

    mac2 = <buffer uint8_t[32] mac2>
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00


  }
  chain_hash_1

  b6 c3 dc a9 8a 6d e5 8e  25 dc f2 aa 1a c8 64 6c
  6e 78 a7 c4 e7 e2 79 43  f2 58 c5 40 41 ea 36 e1

  chain_key_1

  8d ec c9 b9 16 3e 68 e9  cd 3c 98 92 73 5f cc 7c
  ac 60 02 ff bb af 6f 85  6f bf 7c 1b ad c3 71 19

  chain_hash_2

  b6 c3 dc a9 8a 6d e5 8e  25 dc f2 aa 1a c8 64 6c
  6e 78 a7 c4 e7 e2 79 43  f2 58 c5 40 41 ea 36 e1

  chain_key_2

  8d ec c9 b9 16 3e 68 e9  cd 3c 98 92 73 5f cc 7c
  ac 60 02 ff bb af 6f 85  6f bf 7c 1b ad c3 71 19
     |}]

let%expect_test "test_handshake" =
  Crypto.init () |> Or_error.ok_exn ;
  (* local and remote static keys *)
  let static_keypair1 = Crypto.generate () |> Or_error.ok_exn in
  let static_keypair2 = Crypto.generate () |> Or_error.ok_exn in
  let handshake1 : Handshake.t = Handshake.new_handshake () in
  let handshake2 : Handshake.t = Handshake.new_handshake () in
  Handshake.blit_t_remote_static handshake1
    (Public.to_bytes static_keypair2.public) ;
  Handshake.blit_t_remote_static handshake2
    (Public.to_bytes static_keypair1.public) ;
  let shared_static_static1 : bytes =
    Crypto.dh ~secret:static_keypair1.secret ~public:static_keypair2.public
    |> Or_error.ok_exn |> Shared.to_bytes in
  Handshake.blit_t_precomputed_static_static handshake1 shared_static_static1 ;
  let shared_static_static2 : bytes =
    Crypto.dh ~secret:static_keypair2.secret ~public:static_keypair1.public
    |> Or_error.ok_exn |> Shared.to_bytes in
  (* set precomputed_static_static *)
  Handshake.blit_t_precomputed_static_static handshake2 shared_static_static2 ;
  let handshake_initiation : Message.handshake_initiation =
    create_message_initiation ~local_static_public:static_keypair1.public
      handshake1
    |> Or_error.ok_exn in
  let peer1 : peer =
    consume_message_initiation
    (* for testing only! should not be passed in in prod. *)
      ~peer:{handshake= handshake2; keypairs= ref (Keypair.create_empty_ts ())}
      ~msg:handshake_initiation ~local_static:static_keypair2
    |> Or_error.ok_exn in
  let handshake_response : Message.handshake_response =
    create_message_response peer1 |> Or_error.ok_exn in
  let peer2 : peer =
    consume_message_response ~local_static:static_keypair1
      ~handshake:handshake1 handshake_response
    |> Or_error.ok_exn in
  let chain_hash_1, chain_key_1 =
    (Handshake.get_t_hash handshake1, Handshake.get_t_chain_key handshake1)
  in
  let chain_hash_2, chain_key_2 =
    (Handshake.get_t_hash handshake2, Handshake.get_t_chain_key handshake2)
  in
  if not (Bytes.equal chain_hash_1 chain_hash_2) then
    failwith "chain hashes don't match" ;
  if not (Bytes.equal chain_key_1 chain_key_2) then
    failwith "chain keys don't match" ;
  let () = begin_symmetric_session peer1 |> Or_error.ok_exn in
  let () = begin_symmetric_session peer2 |> Or_error.ok_exn in
  test_key_pairs peer1 peer2 |> Or_error.ok_exn ;
  [%expect {|  |}]