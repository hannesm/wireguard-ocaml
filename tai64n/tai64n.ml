open Core
open Stdint

type t = {seconds: uint64; nanoseconds: uint32}

let base = Uint64.of_string "0x400000000000000a"

let time_to_t time =
  let since_epoch = Time_ns.to_span_since_epoch time in
  let ns_since_epoch =
    Time_ns.Span.to_int63_ns since_epoch
    |> Int63.to_int64 |> Uint64.of_int64
  in
  let seconds, nanoseconds =
    let thousand = Uint64.of_int 1000000000 in
    Uint64.(base + (ns_since_epoch / thousand), rem ns_since_epoch thousand)
  in
  {seconds; nanoseconds= Uint64.to_uint32 nanoseconds}

let t_to_bytes {seconds; nanoseconds} =
  let buf = Bytes.create 12 in
  Uint64.to_bytes_big_endian seconds buf 0 ;
  Uint32.to_bytes_big_endian nanoseconds buf 8 ;
  buf

(*let bytes_to_t buf = let secs = EndianBytes.BigEndian.get_int64 buf 0 in
  let ns = EndianBytes.BigEndian.get_int32 buf 8 in {seconds=secs;
  nanoseconds=ns} ;;*)
let whitener_mask = Uint32.of_int (0x1000000 - 1)

let whiten {seconds; nanoseconds} =
  (* CR crichoux: is this right? *)
  (*print_s [%message "nanoseconds before whitening" (Uint32.to_string
    nanoseconds :string)]; *)
  let nanoseconds =
    Uint32.logand nanoseconds (Uint32.lognot whitener_mask)
  in
  (* print_s [%message "nanoseconds after whitening" (Uint32.to_string
     nanoseconds: string)]; *)
  {seconds; nanoseconds}

(* CR crichoux: add tests here, verify all strings *)
let get_timestamp time = time |> time_to_t |> whiten |> t_to_bytes

let now () = get_timestamp (Time_ns.now ())

let after (t1 : bytes) (t2 : bytes) = Bytes.compare t1 t2 > 0

let%expect_test "test_tai64n_monotonic" =
  let old = ref (now ()) in
  let sleep_period =
    Time_ns.Span.to_sec
      (Time_ns.Span.of_int_ns (Uint32.to_int whitener_mask))
  in
  for _ = 0 to 50 do
    let next = now () in
    if after next !old then print_s [%message "whitening insufficient"] ;
    Unix.nanosleep sleep_period |> ignore ;
    let next = now () in
    if not (after next !old) then
      print_s
        [%message
          "not monotonically increasing on whitened nanosecond scale"] ;
    old := next
  done ;
  [%expect {| |}]
