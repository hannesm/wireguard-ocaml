open Core
open Stdint
open Or_error.Let_syntax
open Crypto

(* CR crichoux: this is way too time consuming. worry about clearing and
   managing memory later. *)

(* various nothing-up-my-sleeve constants *)
let _noise_construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
let _wg_identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"
let _wg_label_MAC1 = "mac1----"
let _wg_label_cookie = "cookie--"

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

let create_message_initiation
    ?(* optionally pass in constants for values that should be generated *)
     (* just for testing! *)
    timestamp ?local_ephemeral ~(local_static_public : Public.key)
    ~(handshake : Handshake.t) : Message.handshake_initiation Or_error.t =
  (* CR crichoux: worry about this soon/later device.staticIdentity.RLock()
     defer device.staticIdentity.RUnlock() *)
  (* CR crichoux: worry about this soon handshake.mutex.Lock() defer
     handshake.mutex.Unlock() *)
  let ret = Message.new_handshake_initiation () in
  let%bind () =
    Result.ok_if_true
      (not
         (Crypto.is_zero
            (Handshake.get_t_precomputed_static_static handshake)))
      ~error:(Error.of_string "handshake precomputed static is zero") in
  Handshake.blit_t_hash handshake initial_chain_hash ;
  Handshake.blit_t_chain_key handshake initial_chain_key ;
  (* create ephemeral key *)
  let%bind () =
    let%map local_ephemeral =
      match local_ephemeral with Some le -> Ok le | None -> generate ()
    in
    Handshake.blit_t_ephemeral_keypair handshake local_ephemeral in
  (* assign index *)
  (let local_index : Cstruct.uint32 = Int32.of_int 3 in
   Handshake.set_t_local_index handshake local_index ;
   Message.set_handshake_initiation_sender ret local_index) ;
  (* CR crichoux: TODO device.indexTable.Delete(handshake.localIndex)
     handshake.localIndex, err =
     device.indexTable.NewIndexForHandshake(peer, handshake) *)
  let%bind () =
    Handshake.mix_hash handshake (Handshake.get_t_remote_static handshake)
  in
  let ephemeral = Handshake.get_t_local_ephemeral_public handshake in
  Handshake.mix_key handshake ephemeral ;
  Message.blit_handshake_initiation_ephemeral ret ephemeral ;
  let%bind () = Handshake.mix_hash handshake ephemeral in
  (* encrypt static key *)
  let%bind ephemeral_shared =
    let local_eph_secret =
      Handshake.get_t_local_ephemeral_private handshake in
    let remote_stat_public = Handshake.get_t_remote_static handshake in
    dh
      ~secret:(Secret.of_bytes local_eph_secret)
      ~public:(Public.of_bytes remote_stat_public) in
  let kappa =
    Handshake.mix_key2 handshake (Shared.to_bytes ephemeral_shared) in
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
  Handshake.blit_t_precomputed_static_static handshake
    (Shared.to_bytes kappa) ;
  let%bind signed_timestamp =
    aead_encrypt ~key:kappa ~counter:(Int64.of_int 0) ~message:timestamp
      ~auth_text:(Handshake.get_t_hash handshake) in
  let%map () = Handshake.mix_hash handshake signed_timestamp in
  Message.blit_handshake_initiation_signed_timestamp ret signed_timestamp ;
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
type peer = {handshake: Handshake.t}

let consume_message_initiation
    ?(* for testing only! should not be passed in in prod. *)
    peer ~(msg : Message.handshake_initiation) ~(local_static : keypair) :
    peer Or_error.t =
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
    aead_decrypt ~key:kappa ~counter:(Int64.of_int 0)
      ~ciphertext:signed_static ~auth_text:hash in
  let%bind () = mix_hash ~hash signed_static in
  (* lookup peer *)
  let peer =
    match peer with Some peer -> peer | None -> failwith "unimplemented"
  in
  let handshake = peer.handshake in
  (* CR crichoux: change this to something sensical.... *)
  assert (Bytes.equal peer_pk (Handshake.get_t_remote_static handshake));
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
      Tai64n.after
        (Tai64n.of_bytes timestamp)
        (Tai64n.of_bytes last_timestamp) in
    (* CR crichoux: figure this one out *)
    let ok =
      let last_init_consump =
        Handshake.get_t_last_initiation_consumption handshake in
      ok
      && Time_ns.Span.(Tai64n.diff (Tai64n.now ()) (Tai64n.of_bytes last_init_consump)
         > handshake_initiation_rate) in
    Result.ok_if_true ok
      ~error:(Error.of_string "insufficient time since last initiation")
  in
  Handshake.blit_t_hash handshake hash ;
  Handshake.blit_t_chain_key handshake chain_key ;
  let sender = Message.get_handshake_initiation_sender msg in
  Handshake.set_t_remote_index handshake sender ;
  Handshake.blit_t_remote_ephemeral handshake ephemeral ;
  Handshake.blit_t_last_timestamp handshake timestamp ;
  Handshake.blit_t_last_initiation_consumption handshake (Tai64n.now () |> Tai64n.to_bytes) ;
  Handshake.set_t_state handshake Handshake.Handshake_initiation_consumed ;
  Crypto.zero_buffer hash ;
  Crypto.zero_buffer chain_key ;
  {handshake}

let int_list_to_bytes int_list =
  let char_list = List.map ~f:char_of_int int_list in
  Bytes.of_char_list char_list

let%expect_test "test_create_message_initiation" =
  Crypto.init () |> Or_error.ok_exn ;
  (* all constants from output of wireguard-go tests *)
  (* local and remote static keys *)
  let dev1_static_private =
    int_list_to_bytes
      [ 224; 114; 26; 212; 195; 244; 59; 190; 172; 168; 61; 43; 199; 150; 127
      ; 38; 231; 253; 83; 239; 77; 53; 17; 129; 247; 46; 198; 121; 147; 242
      ; 95; 99 ]
    |> Crypto.Secret.of_bytes in
  let dev1_static_public =
    int_list_to_bytes
      [ 164; 241; 106; 150; 20; 255; 195; 182; 223; 236; 37; 135; 126; 101
      ; 187; 255; 211; 191; 16; 19; 15; 134; 234; 31; 252; 52; 138; 62; 88
      ; 14; 120; 36 ]
    |> Crypto.Public.of_bytes in
  let dev2_static_private =
    int_list_to_bytes
      [ 56; 63; 223; 191; 65; 76; 161; 98; 187; 219; 126; 199; 86; 23; 147
      ; 194; 204; 57; 156; 82; 225; 132; 10; 140; 254; 102; 97; 25; 91; 249
      ; 140; 127 ]
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
      [ 224; 128; 105; 132; 216; 1; 207; 234; 117; 21; 175; 45; 37; 11; 107
      ; 251; 152; 90; 145; 131; 204; 95; 117; 155; 91; 5; 94; 149; 249; 4
      ; 247; 70 ]
    |> Crypto.Secret.of_bytes in
  let dev1_ephemeral_public =
    int_list_to_bytes
      [ 85; 135; 231; 208; 15; 35; 21; 225; 55; 108; 126; 159; 20; 213; 11
      ; 46; 95; 135; 236; 74; 31; 99; 68; 254; 82; 159; 148; 217; 233; 79
      ; 83; 118 ]
    |> Crypto.Public.of_bytes in
  let dev2_ephemeral_private =
    int_list_to_bytes
      [ 80; 9; 108; 30; 226; 174; 138; 236; 151; 228; 202; 108; 93; 98; 246
      ; 194; 113; 195; 125; 36; 126; 70; 193; 172; 144; 191; 209; 249; 221
      ; 188; 199; 98 ]
    |> Crypto.Secret.of_bytes in
  let dev2_ephemeral_public =
    int_list_to_bytes
      [ 15; 210; 28; 84; 230; 108; 56; 68; 19; 52; 180; 101; 114; 37; 13; 99
      ; 224; 79; 227; 122; 85; 100; 224; 195; 22; 64; 247; 160; 65; 149; 57
      ; 49 ]
    |> Crypto.Public.of_bytes in
  (* timestamp *)
  let timestamp =
    int_list_to_bytes [64; 0; 0; 0; 93; 102; 199; 171; 9; 0; 0; 0] |> Tai64n.of_bytes in
  let static_keypair1 =
    {secret= dev1_static_private; public= dev1_static_public} in
  let static_keypair2 =
    {secret= dev2_static_private; public= dev2_static_public} in
  let ephemeral_keypair1 =
    {secret= dev1_ephemeral_private; public= dev1_ephemeral_public} in
  let _ephemeral_keypair2 =
    {secret= dev2_ephemeral_private; public= dev2_ephemeral_public} in
  let handshake1 = Handshake.new_handshake () in
  let handshake2 = Handshake.new_handshake () in
  Handshake.blit_t_remote_static handshake1
    (Public.to_bytes static_keypair2.public) ;
  Handshake.blit_t_remote_static handshake2
    (Public.to_bytes static_keypair1.public) ;
  let shared_static_static1 =
    Crypto.dh ~secret:static_keypair1.secret ~public:static_keypair2.public
    |> Or_error.ok_exn |> Shared.to_bytes in
  Handshake.blit_t_precomputed_static_static handshake1
    shared_static_static1 ;
  let shared_static_static2 =
    Crypto.dh ~secret:static_keypair2.secret ~public:static_keypair1.public
    |> Or_error.ok_exn |> Shared.to_bytes in
  Handshake.blit_t_precomputed_static_static handshake1
    shared_static_static2 ;
  (* set precomputer_static_static *)
  let handshake_initiation =
    create_message_initiation ~local_ephemeral:ephemeral_keypair1 ~timestamp
      ~local_static_public:static_keypair1.public ~handshake:handshake1 |> Or_error.ok_exn
  in
  Message.hexdump_handshake_initiation handshake_initiation ;
  let _ =
    consume_message_initiation
    (* for testing only! should not be passed in in prod. *)
      ~peer:{handshake=handshake2} ~msg:handshake_initiation
      ~local_static:static_keypair2 in
  (*Message.hexdump_handshake_response
    (create_message_response ~local_ephemeral:ephemeral_keypair1 ~timestamp
       ~local_static_public:static_keypair1.public ~handshake:handshake1) ;*)
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
     |}]

(* CR crichoux: take care of this handshake.mutex.RUnLock() *)

(* // update handshake state

   handshake.mutex.Lock()

   handshake.hash = hash handshake.chainKey = chainKey handshake.remoteIndex
   = msg.Sender handshake.remoteEphemeral = msg.Ephemeral
   handshake.lastTimestamp = timestamp handshake.lastInitiationConsumption =
   time.Now() handshake.state = HandshakeInitiationConsumed

   handshake.mutex.Unlock()

   setZero(hash[:]) setZero(chainKey[:])

   return peer } *)

(*
func (device *Device) CreateMessageResponse(peer *Peer) (MessageResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != HandshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	// assign index

	var err error
	device.indexTable.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}

	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = handshake.localIndex
	msg.Receiver = handshake.remoteIndex

	// create ephemeral key

	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = handshake.localEphemeral.publicKey()
	handshake.mixHash(msg.Ephemeral[:])
	handshake.mixKey(msg.Ephemeral[:])

	func() {
		ss := handshake.localEphemeral.sharedSecret(handshake.remoteEphemeral)
		handshake.mixKey(ss[:])
		ss = handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
		handshake.mixKey(ss[:])
	}()

	// add preshared key

	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte

	KDF3(
		&handshake.chainKey,
		&tau,
		&key,
		handshake.chainKey[:],
		handshake.presharedKey[:],
	)

	handshake.mixHash(tau[:])

	func() {
		aead, _ := chacha20poly1305.New(key[:])
		aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, handshake.hash[:])
		handshake.mixHash(msg.Empty[:])
	}()

	handshake.state = HandshakeResponseCreated

	return &msg, nil
}

func (device *Device) ConsumeMessageResponse(msg *MessageResponse) *Peer {
	if msg.Type != MessageResponseType {
		return nil
	}

	// lookup handshake by receiver

	lookup := device.indexTable.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	ok := func() bool {

		// lock handshake state

		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != HandshakeInitiationCreated {
			return false
		}

		// lock private key for reading

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		// finish 3-way DH

		mixHash(&hash, &handshake.hash, msg.Ephemeral[:])
		mixKey(&chainKey, &handshake.chainKey, msg.Ephemeral[:])

		func() {
			ss := handshake.localEphemeral.sharedSecret(msg.Ephemeral)
			mixKey(&chainKey, &chainKey, ss[:])
			setZero(ss[:])
		}()

		func() {
			ss := device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
			mixKey(&chainKey, &chainKey, ss[:])
			setZero(ss[:])
		}()

		// add preshared key (psk)

		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte
		KDF3(
			&chainKey,
			&tau,
			&key,
			chainKey[:],
			handshake.presharedKey[:],
		)
		mixHash(&hash, &hash, tau[:])

		// authenticate transcript

		aead, _ := chacha20poly1305.New(key[:])
		_, err := aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:])
		if err != nil {
			return false
		}
		mixHash(&hash, &hash, msg.Empty[:])
		return true
	}()

	if !ok {
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.state = HandshakeResponseConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return lookup.peer
}

/* Derives a new keypair from the current handshake state
 *
 */
func (peer *Peer) BeginSymmetricSession() error {
	device := peer.device
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// derive keys

	var isInitiator bool
	var sendKey [chacha20poly1305.KeySize]byte
	var recvKey [chacha20poly1305.KeySize]byte

	if handshake.state == HandshakeResponseConsumed {
		KDF2(
			&sendKey,
			&recvKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = true
	} else if handshake.state == HandshakeResponseCreated {
		KDF2(
			&recvKey,
			&sendKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = false
	} else {
		return errors.New("invalid state for keypair derivation")
	}

	// zero handshake

	setZero(handshake.chainKey[:])
	setZero(handshake.hash[:]) // Doesn't necessarily need to be zeroed. Could be used for something interesting down the line.
	setZero(handshake.localEphemeral[:])
	peer.handshake.state = HandshakeZeroed

	// create AEAD instances

	keypair := new(Keypair)
	keypair.send, _ = chacha20poly1305.New(sendKey[:])
	keypair.receive, _ = chacha20poly1305.New(recvKey[:])

	setZero(sendKey[:])
	setZero(recvKey[:])

	keypair.created = time.Now()
	keypair.sendNonce = 0
	keypair.replayFilter.Init()
	keypair.isInitiator = isInitiator
	keypair.localIndex = peer.handshake.localIndex
	keypair.remoteIndex = peer.handshake.remoteIndex

	// remap index

	device.indexTable.SwapIndexForKeypair(handshake.localIndex, keypair)
	handshake.localIndex = 0

	// rotate key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	defer keypairs.Unlock()

	previous := keypairs.previous
	next := keypairs.next
	current := keypairs.current

	if isInitiator {
		if next != nil {
			keypairs.next = nil
			keypairs.previous = next
			device.DeleteKeypair(current)
		} else {
			keypairs.previous = current
		}
		device.DeleteKeypair(previous)
		keypairs.current = keypair
	} else {
		keypairs.next = keypair
		device.DeleteKeypair(next)
		keypairs.previous = nil
		device.DeleteKeypair(previous)
	}

	return nil
}

func (peer *Peer) ReceivedWithKeypair(receivedKeypair *Keypair) bool {
	keypairs := &peer.keypairs
	if keypairs.next != receivedKeypair {
		return false
	}
	keypairs.Lock()
	defer keypairs.Unlock()
	if keypairs.next != receivedKeypair {
		return false
	}
	old := keypairs.previous
	keypairs.previous = keypairs.current
	peer.device.DeleteKeypair(old)
	keypairs.current = keypairs.next
	keypairs.next = nil
	return true
}
 *)
