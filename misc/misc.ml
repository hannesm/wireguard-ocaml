let make_nice_blit func t bytes =
  let cs = Cstruct.of_bytes bytes in
  func cs 0 t
