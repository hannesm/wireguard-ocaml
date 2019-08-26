type t =
| Destination_buffer_too_small
| Incorrect_packet_length
| Unexpected_packet
| Wrong_packet_type
| Wrong_index
| Wrong_key
| Invalid_tai64n_timestamp
| Wrong_tai64n_timestamp
| Invalid_mac
| Invalid_aead_tag
| Invalid_counter
| Invalid_packet
| No_current_session
| Lock_failed
| Connection_expired
| Under_load
[@@deriving sexp_of]
