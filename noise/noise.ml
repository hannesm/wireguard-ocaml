open Core
open Stdint
open Or_error.Let_syntax
open Crypto

let noise_public_key_size = 32

let noise_private_key_size = 32

type noise_state =
  | Handshake_zeroed
  | Handshake_initiation_created
  | Handshake_initiation_consumed
  | Handshake_response_created
  | Handshake_response_consumed

(* various nothing-up-my-sleeve constants *)
let _noise_construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

let _wg_identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"

let _wg_label_MAC1 = "mac1----"

let _wg_label_cookie = "cookie--"

(* initiator.chaining_key = HASH(CONSTRUCTION)*)
let initial_chain_key =
  Bytes.of_string
    "\x60\xe2\x6d\xae\xf3\x27\xef\xc0\x2e\xc3\x35\xe2\xa0\x25\xd2\xd0\x16\xeb\x42\x06\xf8\x72\x77\xf5\x2d\x38\xd1\x98\x8b\x78\xcd\x36"

(* initiator.chaining_hash = HASH(initiator.chaining_key || IDENTIFIER) *)
let initial_chain_hash =
  Bytes.of_string
    "\x22\x11\xb3\x61\x08\x1a\xc5\x66\x69\x12\x43\xdb\x45\x8a\xd5\x32\x2d\x9c\x6c\x66\x22\x93\xe8\xb7\x0e\xe1\x9c\x65\xba\x07\x9e\xf3"

module Noise_message = struct
  (* size of handshake initation message *)
  let msg_initiation_size = 148

  (* size of response message *)
  let msg_response_size = 92

  (* size of cookie reply message *)
  let msg_cookie_reply_size = 64

  (* size of data preceeding content in transport message *)
  let msg_transport_header_size = 16

  (* size of empty transport *)
  let msg_transport_size = msg_transport_header_size + poly1305_tag_size

  (* size of keepalive *)
  let msg_keep_alive_size = msg_transport_size

  (* size of largest handshake releated message *)
  let msg_handshake_size = msg_initiation_size

  (* offsets of interesting things inside transpost messages *)
  let msg_transport_offset_receiver = 4

  let msg_transport_offset_counter = 8

  let msg_transport_offset_content = 16

  type t =
    | Handshake_initiation of
        { sender: Uint32.t
        ; ephemeral: Public.key
        ; signed_static: bytes
        ; signed_timestamp: bytes
        ; mac1: bytes
        ; mac2: bytes }
    | Handshake_response of
        { sender: Uint32.t
        ; receiver: Uint32.t
        ; ephemeral: Public.key
        ; signed_empty: bytes
        ; mac1: bytes
        ; mac2: bytes }
    | Cookie_reply of
        {receiver: Uint32.t; nonce: bytes; signed_cookie: bytes}
    | Transport of {receiver: Uint32.t; counter: Uint64.t; content: bytes}

  let msg_type_to_header = function
    | Handshake_initiation _ -> Bytes.of_string "\x01\x00\x00\x00"
    | Handshake_response _ -> Bytes.of_string "\x02\x00\x00\x00"
    | Cookie_reply _ -> Bytes.of_string "\x03\x00\x00\x00"
    | Transport _ -> Bytes.of_string "\x04\x00\x00\x00"
end

module Handshake = struct
  type t =
    { mutable state: noise_state
    ; (* CR crichoux: add this back? -> mutex : sync.RWMutex *)
      hash: bytes
    ; chain_key: bytes
    ; preshared_key: Shared.key
    ; local_ephemeral: keypair
    ; (* localIndex is used to clear hash-table *)
      mutable local_index: Uint32.t
    ; remote_index: Uint32.t
    ; remote_static: Public.key
    ; remote_ephemeral: Public.key
    ; precomputed_static_static: Shared.key
    ; last_timestamp: bytes
    ; last_initiation_consumption: Time_ns.t
    ; last_sent_handshake: Time_ns.t }

  let clear (t_ref : t ref) : unit =
    Secret.set_zero !t_ref.local_ephemeral.secret ;
    Public.set_zero !t_ref.remote_ephemeral ;
    zero_buffer !t_ref.chain_key ;
    zero_buffer !t_ref.hash ;
    !t_ref.local_index <- Uint32.of_int 0 ;
    !t_ref.state <- Handshake_zeroed
  ;;
end

let mix_key ~(chain_key) ~bytes : unit Or_error.t =
  let c_i = kdf_1 ~key:(Shared.of_bytes chain_key) bytes in
  let%map () = Shared.copy_to_bytes c_i chain_key in
  Shared.set_zero c_i

let mix_key2 ~(chain_key) ~bytes : Shared.key Or_error.t =
  let c_i, kappa = kdf_2 ~key:(Shared.of_bytes chain_key) bytes in
  let%map () = Shared.copy_to_bytes c_i chain_key in
  Shared.set_zero c_i ; kappa

let mix_hash ~(hash) ~bytes : unit Or_error.t =
  let open Crypto in
  let%bind result = hash2 hash bytes in
  let%map () = copy_buffer ~src:result ~dst:hash in
  zero_buffer result

let create_message_initiation ~(local_static_public : Public.key)
    ~(handshake : Handshake.t) : Noise_message.t Or_error.t =
  (* CR crichoux: worry about this soon/later device.staticIdentity.RLock()
     defer device.staticIdentity.RUnlock() *)
  (* CR crichoux: worry about this soon handshake.mutex.Lock() defer
     handshake.mutex.Unlock() *)
  let%bind () =
    Result.ok_if_true
      (Shared.is_zero handshake.precomputed_static_static)
      ~error:(Error.of_string "handshake precomputed static is zero")
  in
  (* create ephemeral key *)
  let%bind () = copy_buffer ~dst:handshake.hash ~src:initial_chain_hash in
  let%bind () =
    copy_buffer ~dst:handshake.chain_key ~src:initial_chain_key
  in
  let%bind () =
    let%bind keypair = generate () in
    let%map () = copy_keypair ~src:keypair ~dst:handshake.local_ephemeral in
    zero_keypair keypair
  in
  (* assign index *)
  handshake.local_index <- Uint32.of_int 3 ;
  (* CR crichoux: TODO device.indexTable.Delete(handshake.localIndex)
     handshake.localIndex, err =
     device.indexTable.NewIndexForHandshake(peer, handshake) *)
  let%bind () =
    mix_hash ~handshake ~bytes:(Public.to_bytes handshake.remote_static)
  in
  let ephemeral = handshake.local_ephemeral.public in
  let%bind () = mix_key ~handshake ~bytes:(Public.to_bytes ephemeral) in
  let%bind () = mix_hash ~handshake ~bytes:(Public.to_bytes ephemeral) in
  (* encrypt static key *)
  let%bind ephemeral_shared =
    dh ~secret:handshake.local_ephemeral.secret
      ~public:handshake.remote_static
  in
  let%bind kappa =
    mix_key2 ~handshake ~bytes:(Shared.to_bytes ephemeral_shared)
  in
  let%bind signed_static =
    aead_encrypt ~key:kappa ~counter:(Int64.of_int 0)
      ~message:(Public.to_bytes local_static_public)
      ~auth_text:handshake.hash
  in
  let%bind () = mix_hash ~handshake ~bytes:signed_static in
  (* encrypt timestamp *)
  let timestamp = Tai64n.now () in
  let%bind kappa =
    mix_key2 ~handshake ~bytes:(Shared.to_bytes ephemeral_shared)
  in
  let%bind () =
    Crypto.Shared.copy ~src:kappa ~dst:handshake.precomputed_static_static
  in
  let%bind signed_timestamp =
    aead_encrypt ~key:kappa ~counter:(Int64.of_int 0) ~message:timestamp
      ~auth_text:handshake.hash
  in
  let%map () = mix_hash ~handshake ~bytes:signed_timestamp in
  Noise_message.Handshake_initiation
    { sender= handshake.local_index
    ; ephemeral
    ; signed_static
    ; signed_timestamp (* CR crichoux: TODO lol *)
    ; mac1= Bytes.create 0
    ; mac2= Bytes.create 0 }
;;

let consume_message_initiation ~(message:Noise_message.t) ~(local_static_public:Public.key): unit Or_error.t =
  let consume_message_initiation_ msg =
    let hash = Bytes.copy initial_chain_hash in
    let chain_key = Bytes.copy initial_chain_key in
    let%bind () = mix_hash ~hash ~bytes:local_static_public in
    let%bind () = mix_hash ~hash ~bytes:msg.ephemeral in
    let%bind () = mix_key ~chain_key ~bytes:(msg.ephemeral) in
    (* CR crichoux: take care of this
  	device.staticIdentity.RLock()
  	defer device.staticIdentity.RUnlock()
    *)

    (* decrypt static key *)
    let%bind ephemeral_shared = dh ~secret:local_static_public ~public:msg.ephemeral in
    let%bind kappa =
      mix_key2 ~hash ~bytes:(Shared.to_bytes ephemeral_shared)
    in
    let%bind peer_pk =
      aead_decrypt ~key:kappa ~counter:(Int64.of_int 0)
        ~ciphertext:msg.signed_static
        ~auth_text:handshake.hash
    in
    let%bind () = mix_hash ~hash ~bytes:msg.signed_static in

    (* lookup peer *)
    let%bind peer = device.lookup_peer peerpk in
    let%bind () =
      Result.ok_if_true
        (Shared.is_zero peer.handshake.precomputed_static_static)
        ~error:(Error.of_string "handshake precomputed static is zero")
    in

    (* verify identity *)
    let%bind kappa =
      mix_key2 ~chain_key ~bytes:(peer.handshake.precomputed_static_static)
    in
    let%bind timestamp =
      aead_decrypt ~key:kappa ~counter:(Int64.of_int 0)
        ~ciphertext:msg.signed_timestamp ~auth_text:handshake.hash
    in
    let%bind () = mix_hash ~hash ~bytes:msg.timestamp in

    (* CR crichoux: take care of this
  	handshake.mutex.RLock()
  	*)

    (* protect against replays, floods *)
    let%bind () =
      let ok = Tai64n.after timestamp handshake.lastTimestamp in
      let ok = ok && time.Since(handshake.lastInitiationConsumption) > HandshakeInitationRate
      Result.ok_if_true ok
        ~error:(Error.of_string "insufficient time since last initiation")
    in

    (* CR crichoux: take care of this
    handshake.mutex.RUnLock()
    *)

    (*
  	// update handshake state

  	handshake.mutex.Lock()

  	handshake.hash = hash
  	handshake.chainKey = chainKey
  	handshake.remoteIndex = msg.Sender
  	handshake.remoteEphemeral = msg.Ephemeral
  	handshake.lastTimestamp = timestamp
  	handshake.lastInitiationConsumption = time.Now()
  	handshake.state = HandshakeInitiationConsumed

  	handshake.mutex.Unlock()

  	setZero(hash[:])
  	setZero(chainKey[:])

  	return peer
  }
  *)
  in
  (* CR crichoux: can we handle this in the type system? *)
  match message with
  | Handshake_initiation contents -> consume_message_initiation_ contents
  | _ -> Or_error.error_s [%message "called consume_message_initiation w/ wrong message type "]
;;

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
