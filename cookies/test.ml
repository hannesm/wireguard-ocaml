open Core
open Or_error.Let_syntax

let int_list_to_bytes (int_list : int list) : bytes =
  let char_list = List.map ~f:char_of_int int_list in
  Bytes.of_char_list char_list

let src = int_list_to_bytes [192; 168; 13; 37; 10; 10; 10]

let%expect_test "test_cookie_mac1_check_from_go" =
  Or_error.ok_exn
    (let%bind key = Crypto.generate () in
     let%bind check = Checker.init key.public in
     let%bind () =
       let msg =
         [ '\x99'; '\xbb'; '\xa5'; '\xfc'; '\x99'; '\xaa'; '\x83'; '\xbd'
         ; '\x7b'; '\x00'; '\xc5'; '\x9a'; '\x4c'; '\xb9'; '\xcf'; '\x62'
         ; '\x40'; '\x23'; '\xf3'; '\x8e'; '\xd8'; '\xd0'; '\x62'; '\x64'
         ; '\x5d'; '\xb2'; '\x80'; '\x13'; '\xda'; '\xce'; '\xc6'; '\x91'
         ; '\x61'; '\xd6'; '\x30'; '\xf1'; '\x32'; '\xb3'; '\xa2'; '\xf4'
         ; '\x7b'; '\x43'; '\xb5'; '\xa7'; '\xe2'; '\xb1'; '\xf5'; '\x6c'
         ; '\x74'; '\x6b'; '\xb0'; '\xcd'; '\x1f'; '\x94'; '\x86'; '\x7b'
         ; '\xc8'; '\xfb'; '\x92'; '\xed'; '\x54'; '\x9b'; '\x44'; '\xf5'
         ; '\xc8'; '\x7d'; '\xb7'; '\x8e'; '\xff'; '\x49'; '\xc4'; '\xe8'
         ; '\x39'; '\x7c'; '\x19'; '\xe0'; '\x60'; '\x19'; '\x51'; '\xf8'
         ; '\xe4'; '\x8e'; '\x02'; '\xf1'; '\x7f'; '\x1d'; '\xcc'; '\x8e'
         ; '\xb0'; '\x07'; '\xff'; '\xf8'; '\xaf'; '\x7f'; '\x66'; '\x82'
         ; '\x83'; '\xcc'; '\x7c'; '\xfa'; '\x80'; '\xdb'; '\x81'; '\x53'
         ; '\xad'; '\xf7'; '\xd8'; '\x0c'; '\x10'; '\xe0'; '\x20'; '\xfd'
         ; '\xe8'; '\x0b'; '\x3f'; '\x90'; '\x15'; '\xcd'; '\x93'; '\xad'
         ; '\x0b'; '\xd5'; '\x0c'; '\xcc'; '\x88'; '\x56'; '\xe4'; '\x3f' ]
         |> Bytes.of_char_list |> Messages.create_dummy in
       Checker.check_macs ~t:check ~msg ~src in
     let%bind () =
       let msg =
         [ '\x33'; '\xe7'; '\x2a'; '\x84'; '\x9f'; '\xff'; '\x57'; '\x6c'
         ; '\x2d'; '\xc3'; '\x2d'; '\xe1'; '\xf5'; '\x5c'; '\x97'; '\x56'
         ; '\xb8'; '\x93'; '\xc2'; '\x7d'; '\xd4'; '\x41'; '\xdd'; '\x7a'
         ; '\x4a'; '\x59'; '\x3b'; '\x50'; '\xdd'; '\x7a'; '\x7a'; '\x8c'
         ; '\x9b'; '\x96'; '\xaf'; '\x55'; '\x3c'; '\xeb'; '\x6d'; '\x0b'
         ; '\x13'; '\x0b'; '\x97'; '\x98'; '\xb3'; '\x40'; '\xc3'; '\xcc'
         ; '\xb8'; '\x57'; '\x33'; '\x45'; '\x6e'; '\x8b'; '\x09'; '\x2b'
         ; '\x81'; '\x2e'; '\xd2'; '\xb9'; '\x66'; '\x0b'; '\x93'; '\x05' ]
         |> Bytes.of_char_list |> Messages.create_dummy in
       Checker.check_macs ~t:check ~msg ~src in
     let msg =
       [ '\x9b'; '\x96'; '\xaf'; '\x55'; '\x3c'; '\xeb'; '\x6d'; '\x0b'; '\x13'
       ; '\x0b'; '\x97'; '\x98'; '\xb3'; '\x40'; '\xc3'; '\xcc'; '\xb8'; '\x57'
       ; '\x33'; '\x45'; '\x6e'; '\x8b'; '\x09'; '\x2b'; '\x81'; '\x2e'; '\xd2'
       ; '\xb9'; '\x66'; '\x0b'; '\x93'; '\x05' ]
       |> Bytes.of_char_list |> Messages.create_dummy in
     Checker.check_macs ~t:check ~msg ~src) ;
  [%expect {| |}]

let%expect_test "test_cookie_reply_from_go" =
  let msg =
    [ '\x6d'; '\xd7'; '\xc3'; '\x2e'; '\xb0'; '\x76'; '\xd8'; '\xdf'; '\x30'
    ; '\x65'; '\x7d'; '\x62'; '\x3e'; '\xf8'; '\x9a'; '\xe8'; '\xe7'; '\x3c'
    ; '\x64'; '\xa3'; '\x78'; '\x48'; '\xda'; '\xf5'; '\x25'; '\x61'; '\x28'
    ; '\x53'; '\x79'; '\x32'; '\x86'; '\x9f'; '\xa0'; '\x27'; '\x95'; '\x69'
    ; '\xb6'; '\xba'; '\xd0'; '\xa2'; '\xf8'; '\x68'; '\xea'; '\xa8'; '\x62'
    ; '\xf2'; '\xfd'; '\x1b'; '\xe0'; '\xb4'; '\x80'; '\xe5'; '\x6b'; '\x3a'
    ; '\x16'; '\x9e'; '\x35'; '\xf6'; '\xa8'; '\xf2'; '\x4f'; '\x9a'; '\x7b'
    ; '\xe9'; '\x77'; '\x0b'; '\xc2'; '\xb4'; '\xed'; '\xba'; '\xf9'; '\x22'
    ; '\xc3'; '\x03'; '\x97'; '\x42'; '\x9f'; '\x79'; '\x74'; '\x27'; '\xfe'
    ; '\xf9'; '\x06'; '\x6e'; '\x97'; '\x3a'; '\xa6'; '\x8f'; '\xc9'; '\x57'
    ; '\x0a'; '\x54'; '\x4c'; '\x64'; '\x4a'; '\xe2'; '\x4f'; '\xa1'; '\xce'
    ; '\x95'; '\x9b'; '\x23'; '\xa9'; '\x2b'; '\x85'; '\x93'; '\x42'; '\xb0'
    ; '\xa5'; '\x53'; '\xed'; '\xeb'; '\x63'; '\x2a'; '\xf1'; '\x6d'; '\x46'
    ; '\xcb'; '\x2f'; '\x61'; '\x8c'; '\xe1'; '\xe8'; '\xfa'; '\x67'; '\x20'
    ; '\x80'; '\x6d' ]
    |> Bytes.of_char_list |> Messages.create_dummy in
  (let%bind key = Crypto.generate () in
   let%bind check = Checker.init key.public in
   let%bind gen = Generator.init key.public in
   let%bind () = Generator.add_macs ~t:gen ~msg in
   let%bind cookie_reply =
     Checker.create_reply ~t:check ~msg ~receiver:(Int32.of_int_exn 1377) ~src
   in
   Generator.consume_reply ~t:gen ~msg:cookie_reply)
  |> Or_error.ok_exn ;
  [%expect {| |}]

let is_error = function
  | Ok _ -> Or_error.error_s [%message "this should be an error!"]
  | Error _ -> Ok ()

let check_mac2 ~gen ~check ~msg =
  let%bind () = Generator.add_macs ~t:gen ~msg in
  let%bind () = Checker.check_macs ~t:check ~msg ~src in
  Messages.xor_dummy '\x20' msg ;
  let%bind () = Checker.check_macs ~t:check ~msg ~src |> is_error in
  Messages.xor_dummy '\x20' msg ;
  let src_bad1 = int_list_to_bytes [192; 168; 13; 37; 40; 01] in
  let%bind () = Checker.check_macs ~t:check ~msg ~src:src_bad1 |> is_error in
  let src_bad2 = int_list_to_bytes [192; 168; 13; 38; 40; 01] in
  Checker.check_macs ~t:check ~msg ~src:src_bad2 |> is_error

let%expect_test "test_cookie_mac2_check_from_go" =
  (let%bind key = Crypto.generate () in
   let%bind check = Checker.init key.public in
   let%bind gen = Generator.init key.public in
   let%bind () =
     let msg =
       [ '\x03'; '\x31'; '\xb9'; '\x9e'; '\xb0'; '\x2a'; '\x54'; '\xa3'; '\xc1'
       ; '\x3f'; '\xb4'; '\x96'; '\x16'; '\xb9'; '\x25'; '\x15'; '\x3d'; '\x3a'
       ; '\x82'; '\xf9'; '\x58'; '\x36'; '\x86'; '\x3f'; '\x13'; '\x2f'; '\xfe'
       ; '\xb2'; '\x53'; '\x20'; '\x8c'; '\x3f'; '\xba'; '\xeb'; '\xfb'; '\x4b'
       ; '\x1b'; '\x22'; '\x02'; '\x69'; '\x2c'; '\x90'; '\xbc'; '\xdc'; '\xcf'
       ; '\xcf'; '\x85'; '\xeb'; '\x62'; '\x66'; '\x6f'; '\xe8'; '\xe1'; '\xa6'
       ; '\xa8'; '\x4c'; '\xa0'; '\x04'; '\x23'; '\x15'; '\x42'; '\xac'; '\xfa'
       ; '\x38' ]
       |> Bytes.of_char_list |> Messages.create_dummy in
     check_mac2 ~gen ~check ~msg in
   let msg =
     [ '\x0e'; '\x2f'; '\x0e'; '\xa9'; '\x29'; '\x03'; '\xe1'; '\xf3'; '\x24'
     ; '\x01'; '\x75'; '\xad'; '\x16'; '\xa5'; '\x66'; '\x85'; '\xca'; '\x66'
     ; '\xe0'; '\xbd'; '\xc6'; '\x34'; '\xd8'; '\x84'; '\x09'; '\x9a'; '\x58'
     ; '\x14'; '\xfb'; '\x05'; '\xda'; '\xf5'; '\x90'; '\xf5'; '\x0c'; '\x4e'
     ; '\x22'; '\x10'; '\xc9'; '\x85'; '\x0f'; '\xe3'; '\x77'; '\x35'; '\xe9'
     ; '\x6b'; '\xc2'; '\x55'; '\x32'; '\x46'; '\xae'; '\x25'; '\xe0'; '\xe3'
     ; '\x37'; '\x7a'; '\x4b'; '\x71'; '\xcc'; '\xfc'; '\x91'; '\xdf'; '\xd6'
     ; '\xca'; '\xfe'; '\xee'; '\xce'; '\x3f'; '\x77'; '\xa2'; '\xfd'; '\x59'
     ; '\x8e'; '\x73'; '\x0a'; '\x8d'; '\x5c'; '\x24'; '\x14'; '\xca'; '\x38'
     ; '\x91'; '\xb8'; '\x2c'; '\x8c'; '\xa2'; '\x65'; '\x7b'; '\xbc'; '\x49'
     ; '\xbc'; '\xb5'; '\x58'; '\xfc'; '\xe3'; '\xd7'; '\x02'; '\xcf'; '\xf7'
     ; '\x4c'; '\x60'; '\x91'; '\xed'; '\x55'; '\xe9'; '\xf9'; '\xfe'; '\xd1'
     ; '\x44'; '\x2c'; '\x75'; '\xf2'; '\xb3'; '\x5d'; '\x7b'; '\x27'; '\x56'
     ; '\xc0'; '\x48'; '\x4f'; '\xb0'; '\xba'; '\xe4'; '\x7d'; '\xd0'; '\xaa'
     ; '\xcd'; '\x3d'; '\xe3'; '\x50'; '\xd2'; '\xcf'; '\xb9'; '\xfa'; '\x4b'
     ; '\x2d'; '\xc6'; '\xdf'; '\x3b'; '\x32'; '\x98'; '\x45'; '\xe6'; '\x8f'
     ; '\x1c'; '\x5c'; '\xa2'; '\x20'; '\x7d'; '\x1c'; '\x28'; '\xc2'; '\xd4'
     ; '\xa1'; '\xe0'; '\x21'; '\x52'; '\x8f'; '\x1c'; '\xd0'; '\x62'; '\x97'
     ; '\x48'; '\xbb'; '\xf4'; '\xa9'; '\xcb'; '\x35'; '\xf2'; '\x07'; '\xd3'
     ; '\x50'; '\xd8'; '\xa9'; '\xc5'; '\x9a'; '\x0f'; '\xbd'; '\x37'; '\xaf'
     ; '\xe1'; '\x45'; '\x19'; '\xee'; '\x41'; '\xf3'; '\xf7'; '\xe5'; '\xe0'
     ; '\x30'; '\x3f'; '\xbe'; '\x3d'; '\x39'; '\x64'; '\x00'; '\x7a'; '\x1a'
     ; '\x51'; '\x5e'; '\xe1'; '\x70'; '\x0b'; '\xb9'; '\x77'; '\x5a'; '\xf0'
     ; '\xc4'; '\x8a'; '\xa1'; '\x3a'; '\x77'; '\x1a'; '\xe0'; '\xc2'; '\x06'
     ; '\x91'; '\xd5'; '\xe9'; '\x1c'; '\xd3'; '\xfe'; '\xab'; '\x93'; '\x1a'
     ; '\x0a'; '\x4c'; '\xbb'; '\xf0'; '\xff'; '\xdc'; '\xaa'; '\x61'; '\x73'
     ; '\xcb'; '\x03'; '\x4b'; '\x71'; '\x68'; '\x64'; '\x3d'; '\x82'; '\x31'
     ; '\x41'; '\xd7'; '\x8b'; '\x22'; '\x7b'; '\x7d'; '\xa1'; '\xd5'; '\x85'
     ; '\x6d'; '\xf0'; '\x1b'; '\xaa' ]
     |> Bytes.of_char_list |> Messages.create_dummy in
   check_mac2 ~gen ~check ~msg)
  |> Or_error.ok_exn ;
  [%expect {| |}]
