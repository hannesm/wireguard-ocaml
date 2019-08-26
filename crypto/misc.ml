open Core

let constant_time_byte_eq (x:char) (y:char) : int =
    let x, y = int_of_char x, int_of_char y in
    let z = ref (lnot (x lxor y)) in
    z := !z land (!z lsr 4);
    z := !z land (!z lsr 2);
    z := !z land (!z lsr 1);
    !z
;;

let is_zero bytes : bool =
  let acc = ref 1 in
  for i = 0 to Bytes.length bytes do
    acc := !acc
      land (constant_time_byte_eq (Bytes.get bytes i) '\x00')
  done;
  !acc = 1
;;

let set_zero bytes : unit =
  Bytes.fill ~pos:0 ~len:(Bytes.length bytes) bytes '\x00'
;;
