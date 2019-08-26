open Core

type t = {
  seconds : int64;
  nanoseconds : int32;
}

let time_to_t time =
  let since_epoch = Time_ns.to_span_since_epoch time in
  let ns_since_epoch =
    Time_ns.Span.to_int63_ns since_epoch |> Int63.to_int64
  in
  let seconds, nanoseconds =
    let thousand = Int64.of_int 1000 in
    Int64.(ns_since_epoch / thousand, rem ns_since_epoch thousand)
  in
  {seconds; nanoseconds=Int64.to_int32_trunc nanoseconds}
;;

let t_to_bytes {seconds; nanoseconds} =
  let buf = Bytes.create 12 in
  EndianBytes.BigEndian.set_int64 buf 0 seconds ;
  EndianBytes.BigEndian.set_int32 buf 8 nanoseconds;
  buf
;;

(*let bytes_to_t buf =
  let secs = EndianBytes.BigEndian.get_int64 buf 0 in
  let ns = EndianBytes.BigEndian.get_int32 buf 8 in
  {seconds=secs; nanoseconds=ns}
;;*)

let whitener_mask = (0x8000000 - 1)

let whiten {seconds; nanoseconds} =
  (* CR crichoux: is this right? *)
  let nanoseconds = Int32.of_int_trunc (Int32.to_int_trunc nanoseconds land whitener_mask) in
  {seconds; nanoseconds}
;;

(* CR crichoux: add tests here, verify all strings *)
let get_timestamp time =
  time |> time_to_t |> whiten |> t_to_bytes
;;

let now () = get_timestamp (Time_ns.now ())

let after (t1 : bytes) (t2: bytes) =
  Bytes.compare t1 t2 > 0
;;

let%expect_test "test_tai64n_monotonic" =
  let old = ref (now ()) in
  let sleep_period =
    Time_ns.Span.to_sec (Time_ns.Span.of_int_ns (whitener_mask + 1))
  in
  for _ = 0 to 50 do
    let next = now () in
    if after next !old then print_s [%message "whitening insufficient"];
    Unix.nanosleep sleep_period |> ignore;
    let next = now () in
    if not (after next !old) then print_s [%message "not monotonically increasing on whitened nanosecond scale"];
    old := next
  done;
  [%expect {| |}]
;;
