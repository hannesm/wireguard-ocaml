open Core

val siphash : key:bytes -> input:bytes -> bytes Or_error.t
