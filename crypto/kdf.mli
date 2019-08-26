open Key

val kdf_1 : key:(shared_key) -> bytes -> shared_key

val kdf_2 : key:(shared_key) -> bytes -> shared_key * shared_key

val kdf_3 : key:(shared_key) -> bytes -> shared_key * shared_key * shared_key
