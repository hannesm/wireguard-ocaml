open Core
open Key

let secret_key_length = 32
let public_key_length = 32
let shared_key_length = 32

external generate_ : bytes -> bytes -> int = "caml_crypto_gen_keypair"

let generate () =
  let public = Bytes.create public_key_length in
  let secret = Bytes.create secret_key_length in
  if generate_ public secret < 0 then
    Or_error.error_s [%message "failed to generate ed25519 keypair"]
  else
    Or_error.return
      {secret= Secret.of_bytes secret; public= Public.of_bytes public}

(* CURRENTLY DOES NOT WORK!! DO NOT USE!! *)
(* external gen_public_ : bytes -> bytes -> int =
   "caml_crypto_gen_pubkey_from_ed25519_secret"

   let _gen_public secret = print_s [%message (secret : Secret.key)]; let
   secret = Secret.to_bytes secret in print_s [%message (secret : bytes)]; let
   public = Bytes.create public_key_length in print_s [%message (public :
   bytes)]; if gen_public_ public secret < 0 then Or_error.error_s [%message
   "failed to generate ed25519 pubkey from secret"] else (print_s [%message
   (public : bytes)]; print_s [%message (secret : bytes)]; Or_error.return
   (Public.of_bytes public)) ;; *)

external dh_ : bytes -> bytes -> bytes -> int = "caml_crypto_dh"

let dh ~(public : Public.key) ~(secret : Secret.key) =
  let shared = Bytes.create shared_key_length in
  let secret = Secret.to_bytes secret in
  let public = Public.to_bytes public in
  if dh_ shared secret public < 0 then
    Or_error.error_s [%message "failed to do ecdh with provided key material"]
  else Or_error.return (Shared.of_bytes shared)

let handle ~default (or_error : 'a Or_error.t) : 'a =
  match or_error with
  | Ok a -> a
  | Error e ->
      print_s [%message (e : Error.t)] ;
      default

let dummy_keypair () =
  { secret= Secret.of_bytes (Bytes.create 0)
  ; public= Public.of_bytes (Bytes.create 0) }

(* let%expect_test "check generating public from private" = Initialize.init ()
   |> handle ~default:() ; let key = generate () |> handle
   ~default:(dummy_keypair ()) in let public_generated = gen_public key.secret
   |> handle ~default:(Public.of_bytes (Bytes.create 1)) in print_s [%message
   (public_generated : Public.key) (key.public : Public.key)]; print_s
   [%message (Public.equals public_generated key.public : bool)] ; [%expect {|
   ("Shared.equals shared1 shared2" true) |}] ;;*)

let%expect_test "check generation and ecdh" =
  Initialize.init () |> handle ~default:() ;
  let k1 = generate () |> handle ~default:(dummy_keypair ()) in
  let k2 = generate () |> handle ~default:(dummy_keypair ()) in
  let shared1 =
    dh ~public:k2.public ~secret:k1.secret
    |> handle ~default:(Shared.of_bytes (Bytes.create 0)) in
  let shared2 =
    dh ~public:k1.public ~secret:k2.secret
    |> handle ~default:(Shared.of_bytes (Bytes.create 0)) in
  print_s [%message (Shared.equals shared1 shared2 : bool)] ;
  [%expect {| ("Shared.equals shared1 shared2" true) |}]
