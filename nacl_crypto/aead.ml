open Core

type data_with_len = Bytes.t * int64

let add_len bytes = bytes, Bytes.length bytes |> Int.to_int64

external encrypt_
  :  data_with_len (* dst ciphertext *)
  -> data_with_len (* src message *)
  -> data_with_len (* src auth_text *)
  -> Bytes.t (* nonce *)
  -> Bytes.t (* key *)
  -> int
  = "caml_crypto_aead_chacha20poly1305_encrypt"

external decrypt_
  :  data_with_len (* dst message *)
  -> data_with_len (* src ciphertext *)
  -> data_with_len (* src auth_text *)
  -> Bytes.t (* nonce *)
  -> Bytes.t (* key *)
  -> int
  = "caml_crypto_aead_chacha20poly1305_decrypt"

let crypto_aead_chacha20poly1305_ABYTES = 16

let nonce_from_counter counter =
  let buf = Bytes.make 12 '\x00' in
  EndianBytes.LittleEndian.set_int64 buf 4 counter;
  buf
;;

let encrypt ~key ~counter ~message ~auth_text =
  let nonce = nonce_from_counter counter in
  let m_with_len = add_len message in
  let c_with_len =
    let c_buf =
      Bytes.create
        ((snd m_with_len |> Int.of_int64_exn) + crypto_aead_chacha20poly1305_ABYTES)
    in
    add_len c_buf
  in
  let auth_with_len = add_len auth_text in
  let status = encrypt_ c_with_len m_with_len auth_with_len nonce key in
  if status < 0
  then Or_error.error_s [%message "failed to encrypt w/ aead" (status : int)]
  else Or_error.return (fst c_with_len)
;;

let decrypt ~key ~counter ~ciphertext ~auth_text =
  let nonce = nonce_from_counter counter in
  let c_with_len = add_len ciphertext in
  let m_with_len =
    let m_buf =
      Bytes.create
        ((snd c_with_len |> Int.of_int64_exn) - crypto_aead_chacha20poly1305_ABYTES)
    in
    add_len m_buf
  in
  let auth_with_len = add_len auth_text in
  let status = decrypt_ m_with_len c_with_len auth_with_len nonce key in
  if status < 0
  then Or_error.error_s [%message "failed to decrypt w/ aead" (status : int)]
  else Or_error.return (fst m_with_len)
;;

let%expect_test "test-aead-encrypt-decrypt" =
  Initialize.init () |> Or_error.ok_exn;
  let message = Bytes.of_string "test" in
  let auth_text = Bytes.of_string "123456" in
  let key = Key.random_buffer 32 in
  let counter = Int.to_int64 50000 in
  let ciphertext = encrypt ~key ~counter ~message ~auth_text |> Or_error.ok_exn in
  let thing = decrypt ~key ~counter ~ciphertext ~auth_text |> Or_error.ok_exn in
  print_string (Bytes.to_string thing);
  [%expect {| test |}]
;;
