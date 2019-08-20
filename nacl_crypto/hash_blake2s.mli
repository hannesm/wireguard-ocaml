open Core

val hash : bytes -> bytes Or_error.t
val hash2 : bytes -> bytes -> bytes Or_error.t
val mac : input:bytes -> key:bytes -> bytes Or_error.t
val hmac : input:bytes -> key:bytes -> bytes
