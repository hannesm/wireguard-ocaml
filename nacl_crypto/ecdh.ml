open Core
open Key

let secret_key_length = 32

let public_key_length = 32

let shared_key_length = 32

external gen_keypair_ : public key -> secret key -> int
  = "caml_crypto_gen_keypair"

let generate () =
  let public : public key = Bytes.create public_key_length in
  let secret : secret key = Bytes.create secret_key_length in
  if gen_keypair_ public secret < 0 then
    Or_error.error_s [%message "failed to generate ed25519 keypair"]
  else Or_error.return {secret; public}

external dh_ : shared key -> secret key -> public key -> int
  = "caml_crypto_dh"

let dh ~(public : public key) ~(secret : secret key) =
  let shared = Bytes.create shared_key_length in
  if dh_ shared secret public < 0 then
    Or_error.error_s
      [%message "failed to do ecdh with provided key material"]
  else Or_error.return shared

let%expect_test "check generation and ecdh" =
  Initialize.init () |> Or_error.ok_exn ;
  let k1 = generate () |> Or_error.ok_exn in
  let k2 = generate () |> Or_error.ok_exn in
  let shared1 = dh ~public:k2.public ~secret:k1.secret |> Or_error.ok_exn in
  let shared2 = dh ~public:k1.public ~secret:k2.secret |> Or_error.ok_exn in
  print_string (Bool.to_string (Bytes.equal shared1 shared2)) ;
  [%expect {| true |}]
