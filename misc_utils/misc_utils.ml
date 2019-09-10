let make_nice_blit func t bytes =
  let cs = Cstruct.of_bytes bytes in
  func cs 0 t

module Rwlock = struct
  type t =
    { reader_count: int ref
    ; writer_here: bool ref
    ; mutex: Mutex.t
    ; reader_can_enter: Condition.t
    ; writer_can_enter: Condition.t }

  let create () =
    { reader_count= ref 0
    ; writer_here= ref false
    ; mutex= Mutex.create ()
    ; reader_can_enter= Condition.create ()
    ; writer_can_enter= Condition.create () }

  let read_lock t =
    Mutex.lock t.mutex ;
    while not !(t.writer_here) do
      Condition.wait t.reader_can_enter t.mutex
    done ;
    t.reader_count := !(t.reader_count) + 1 ;
    Mutex.unlock t.mutex

  let read_unlock t =
    Mutex.lock t.mutex ;
    t.reader_count := !(t.reader_count) - 1 ;
    if !(t.reader_count) = 0 then Condition.signal t.writer_can_enter ;
    Mutex.unlock t.mutex

  let write_lock t =
    Mutex.lock t.mutex ;
    while !(t.reader_count) > 0 || !(t.writer_here) do
      Condition.wait t.writer_can_enter t.mutex
    done ;
    t.writer_here := true ;
    Mutex.unlock t.mutex

  let write_unlock t =
    Mutex.lock t.mutex ;
    t.writer_here := false ;
    Condition.signal t.writer_can_enter ;
    Condition.broadcast t.reader_can_enter ;
    Mutex.unlock t.mutex
end
