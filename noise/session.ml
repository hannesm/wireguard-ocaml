open Core
open Crypto.Key

(* Where encrypted data resides in a data packet *)
let _data_offset : int = 16
(* The overhead of the AEAD *)
let _aead_size : int = 16

(* Receiving buffer constants*)
let word_size : int = 64
(* Suffice to reorder 64*16 = 1024 packets; can be increased at will *)
let n_words : int = 16
let n_bits : int64 = Int64.of_int (word_size * n_words)
let n_bytes : int64 = Int64.(n_bits / (of_int 8))

(* In order to avoid replays while allowing for some reordering of the packets, we keep a
   bitmap of received packets, and the value of the highest counter *)
(* this is some sort of rotating buffer for tracking these *)
module Receiving_key_counter_validator = struct
  type t = {
    (* CR crichoux: should i be worried about signedness here? probably! *)
    mutable next: int64;
    (* used to estimate packet loss *)
    mutable receive_cnt: int64;
    (* CR crichoux: known size at compile time??? *)
    bitmap: Bytes.t;
  }

  let create () =
    let next = Int64.zero in
    let receive_cnt = Int64.zero in
    let bitmap = Bytes.make (Int64.to_int_trunc n_bytes) '\x00' in
    {next; receive_cnt; bitmap}
    ;;

  (* CR crichoux: inline me *)
  let set_bit t (idx : int64) : unit =
    let bit_idx = Int64.to_int_trunc (Int64.rem idx n_bits) in
    let byte, bit  = bit_idx / 8, bit_idx mod 8 in
    let replacement_byte = (Bytes.get t.bitmap byte |> int_of_char) lor (1 lsl bit) in
    Bytes.set t.bitmap byte (char_of_int replacement_byte)
  ;;

  (* CR crichoux: inline me *)
  let clear_bit t (idx : int64) : unit =
    let bit_idx = Int64.to_int_trunc (Int64.rem idx n_bits) in
    let byte, bit  = bit_idx / 8, bit_idx mod 8 in
    let replacement_byte = (Bytes.get t.bitmap byte |> int_of_char) land (lnot (1 lsl bit)) in
    Bytes.set t.bitmap byte (char_of_int replacement_byte)
  ;;

  (* clear word containing idx *)
  (* CR crichoux: test this logic *)
  (* CR crichoux: inline me *)
  let clear_word t (idx : int64) : unit =
    let bit_idx = Int64.to_int_trunc (Int64.rem idx n_bits) in
    let word = bit_idx / word_size in
    for i = 0 to 7 do
      Bytes.set t.bitmap (word + i) '\x00'
    done
  ;;

  (* Returns true if bit is set, false otherwise *)
  (* CR crichoux: inline me *)
  let check_bit t (idx : int64) : bool =
    let bit_idx = Int64.to_int_trunc (Int64.rem idx n_bits) in
    let byte = (bit_idx / 8) in
    let bit = (bit_idx mod 8) in
    (int_of_char (Bytes.get t.bitmap byte) lsr bit) land 1 = 1
  ;;

  (* Returns true if the counter was not yet received, and is not too far back *)
  (* CR crichoux: inline me *)
  let will_accept t (counter : int64) : bool =
    (* As long as the counter is growing no replay took place for sure *)
    counter >= t.next ||
    (* Drop if too far back *)
    (not (Int64.(counter + n_bits < t.next) || check_bit t counter))
  ;;

  (* CR crichoux: inline me *)
  let mark_did_receive t (counter : int64) : (unit, Noise_errors.t) Result.t =
    (* Drop if too far back *)
    if Int64.(counter + n_bits < t.next) then Error Noise_errors.Invalid_counter
    (* Usually the packets arrive in order
       in that case we simply mark the bit and increment the counter *)
    else if counter = t.next then (t.next <- Int64.succ t.next; Ok ())
    (* A packet arrived out of order, check if it is valid, and mark *)
    else if counter < t.next then (
      if check_bit t counter
      then Error (Noise_errors.Invalid_counter)
      else (set_bit t counter; Ok ())
    )
    (* Packets where dropped, or maybe reordered, skip them and mark unused *)
    else if Int64.(counter - t.next >= n_bits) then
      (* Too far ahead, clear all the bits *)
      (* CR crichoux: i am reasonably sure this is an error....? *)
      (Bytes.fill t.bitmap ~pos:0 ~len:(Int64.to_int_trunc n_bytes) '\x00'; Ok ())
    else (
      let i = ref t.next in
      while not (Int64.(!i % of_int word_size = zero)) && !i < counter do
        (* Clear until i aligned to word size *)
        clear_bit t !i;
        i := Int64.succ !i;
      done;
      while Int64.(!i + of_int word_size < counter) do
        (* Clear whole word at a time *)
        clear_word t !i;
        i := Int64.(!i + of_int word_size land zero - of_int word_size) ;
      done;
      while !i < counter do
        (* Clear any remaining bits *)
        clear_bit t !i;
        i := Int64.succ !i;
      done;
      set_bit t counter;
      t.next <- Int64.succ counter;
      Ok ()
    )
  ;;

end

type t =
  {
    receiving_index : int32;
    sending_index : int32;
    receiver : shared_key;
    sender : shared_key;
    sending_key_counter : int64;
    (* CR crichoux: does this need a mutex on it like in boringtun? *)
    receiving_key_counter : Receiving_key_counter_validator.t;
  }

let create ~local_index ~peer_index ~receiving_key ~sending_key =
  {receiving_index=local_index;
  sending_index=peer_index;
  receiver = Crypto.Key.shared_of_bytes receiving_key;
  sender = Crypto.Key.shared_of_bytes sending_key;
  sending_key_counter = Int64.zero;
  receiving_key_counter = Receiving_key_counter_validator.create ()}
;;

let local_index t : int32 = t.receiving_index;;

let _receiving_counter_quick_check t (counter : int64) : (unit, Noise_errors.t) Result.t =
  Result.ok_if_true (Receiving_key_counter_validator.will_accept t.receiving_key_counter counter) ~error:(Noise_errors.Invalid_counter)
;;

let _receiving_counter_mark t (counter : int64) : (unit, Noise_errors.t) Result.t =
  let ret = Receiving_key_counter_validator.mark_did_receive t.receiving_key_counter counter in
  if Result.is_ok ret then t.receiving_key_counter.receive_cnt <- Int64.succ t.receiving_key_counter.receive_cnt;
  ret
;;
(* src - an IP packet from the interface
   dst - pre-allocated space to hold the encapsulating UDP packet
          to send over the network *)
(* returns the size of the formatted packet *)
(*
let DATA_OVERHEAD_SZ = 32;
let format_packet_data ~(src:bytes) ~(dst:bytes) t : (int, ) Result.t =
    if Bytes.length dst < Bytes.length src + DATA_OVERHEAD_SZ {
        panic!("The destination buffer is too small");
    }

    let sending_key_counter = self.sending_key_counter.fetch_add(1, Ordering::Relaxed) as u64;

    let (message_type, rest) = dst.split_at_mut(4);
    let (receiver_index, rest) = rest.split_at_mut(4);
    let (counter, data) = rest.split_at_mut(8);

    message_type.copy_from_slice(&super::DATA.to_le_bytes());
    receiver_index.copy_from_slice(&self.sending_index.to_le_bytes());
    counter.copy_from_slice(&sending_key_counter.to_le_bytes());

    // TODO: spec requires padding to 16 bytes, but actually works fine without it
    #[cfg(not(target_arch = "arm"))]
    let n = {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&sending_key_counter.to_le_bytes());
        data[..src.len()].copy_from_slice(src);
        seal_in_place(
            &self.sender,
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&[]),
            &mut data[..src.len() + aead_size],
            aead_size,
        )
        .unwrap()
    };

    #[cfg(target_arch = "arm")]
    let n = self.sender.seal_wg(
        sending_key_counter,
        &[],
        src,
        &mut data[..src.len() + aead_size],
    );

    &mut dst[..data_offset + n]
}

// packet - a data packet we received from the network
// dst - pre-allocated space to hold the encapsulated IP packet, to send to the interface
//       dst will always take less space than src
// return the size of the encapsulated packet on success
pub(super) fn receive_packet_data<'a>(
    &self,
    packet: PacketData,
    dst: &'a mut [u8],
) -> Result<&'a mut [u8], WireGuardError> {
    let ct_len = packet.encrypted_encapsulated_packet.len();
    if dst.len() < ct_len {
        // This is a very incorrect use of the library, therefore panic and not error
        panic!("The destination buffer is too small");
    }
    if packet.receiver_idx != self.receiving_index {
        return Err(WireGuardError::WrongIndex);
    }
    // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
    self.receiving_counter_quick_check(packet.counter)?;

    #[cfg(not(target_arch = "arm"))]
    let ret = {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&packet.counter.to_le_bytes());
        dst[..ct_len].copy_from_slice(packet.encrypted_encapsulated_packet);
        open_in_place(
            &self.receiver,
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&[]),
            0,
            &mut dst[..ct_len],
        )
        .map_err(|_| WireGuardError::InvalidAeadTag)?
    };

    #[cfg(target_arch = "arm")]
    let ret = self.receiver.open_wg(
        packet.counter,
        &[],
        packet.encrypted_encapsulated_packet,
        dst,
    )?;

    // After decryption is done, check counter again, and mark as received
    self.receiving_counter_mark(packet.counter)?;
    Ok(ret)
}

// Returns the estimated downstream packet loss for this session
pub(super) fn current_packet_cnt(&self) -> (u64, u64) {
    let counter_validator = self.receiving_key_counter.lock();
    (counter_validator.next, counter_validator.receive_cnt)
}
}

#[cfg(test)]
mod tests {
use super::*;
#[test]
fn test_replay_counter() {
    let mut c: ReceivingKeyCounterValidator = Default::default();

    assert!(c.mark_did_receive(0).is_ok());
    assert!(c.mark_did_receive(0).is_err());
    assert!(c.mark_did_receive(1).is_ok());
    assert!(c.mark_did_receive(1).is_err());
    assert!(c.mark_did_receive(63).is_ok());
    assert!(c.mark_did_receive(63).is_err());
    assert!(c.mark_did_receive(15).is_ok());
    assert!(c.mark_did_receive(15).is_err());

    for i in 64..n_bits + 128 {
        assert!(c.mark_did_receive(i).is_ok());
        assert!(c.mark_did_receive(i).is_err());
    }

    assert!(c.mark_did_receive(n_bits * 3).is_ok());
    for i in 0..=n_bits * 2 {
        assert!(!c.will_accept(i));
        assert!(c.mark_did_receive(i).is_err());
    }
    for i in n_bits * 2 + 1..n_bits * 3 {
        assert!(c.will_accept(i));
    }

    for i in (n_bits * 2 + 1..n_bits * 3).rev() {
        assert!(c.mark_did_receive(i).is_ok());
        assert!(c.mark_did_receive(i).is_err());
    }

    assert!(c.mark_did_receive(n_bits * 3 + 70).is_ok());
    assert!(c.mark_did_receive(n_bits * 3 + 71).is_ok());
    assert!(c.mark_did_receive(n_bits * 3 + 72).is_ok());
    assert!(c.mark_did_receive(n_bits * 3 + 72 + 125).is_ok());
    assert!(c.mark_did_receive(n_bits * 3 + 63).is_ok());

    assert!(c.mark_did_receive(n_bits * 3 + 70).is_err());
    assert!(c.mark_did_receive(n_bits * 3 + 71).is_err());
    assert!(c.mark_did_receive(n_bits * 3 + 72).is_err());
}
}
*)
