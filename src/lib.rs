#![warn(
  clippy::cargo,
  clippy::nursery,
  clippy::pedantic,
  missing_debug_implementations,
  missing_docs,
  rust_2018_idioms
)]
#![deny(unsafe_code)]
#![no_std]

//! [ECB-Mix-ECB][1] (EME) block cipher mode implementation.
//!
//! # Usage example
//! ```
//! use aes::Aes128;
//! use eme_mode::{block_modes::BlockMode, block_padding::Pkcs7, Eme};
//!
//! type Aes128Eme = Eme<Aes128, Pkcs7>;
//!
//! let key = [0; 16];
//! let iv = [1; 16];
//! let plaintext = b"Hello world!";
//! let cipher = Aes128Eme::new_from_slices(&key, &iv).unwrap();
//!
//! // buffer must have enough space for message+padding
//! let mut buffer = [0u8; 16];
//! // copy message to the buffer
//! let pos = plaintext.len();
//! buffer[..pos].copy_from_slice(plaintext);
//! let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
//!
//! assert_eq!(
//!   ciphertext,
//!   [147, 227, 119, 228, 187, 150, 249, 88, 176, 145, 53, 209, 217, 99, 70, 245]
//! );
//!
//! // re-create cipher mode instance
//! let cipher = Aes128Eme::new_from_slices(&key, &iv).unwrap();
//! let mut buf = ciphertext.to_vec();
//! let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();
//!
//! assert_eq!(decrypted_ciphertext, plaintext);
//! ```
//!
//! [1]: https://eprint.iacr.org/2003/147.pdf

#[cfg(feature = "std")]
extern crate std;

use block_modes::BlockMode;
use block_padding::Padding;
use cipher::{
  generic_array::{typenum::U16, ArrayLength, GenericArray},
  BlockCipher, BlockDecrypt, BlockEncrypt,
};
use core::marker::PhantomData;

pub use block_modes;
pub use block_padding;
pub use cipher;

type Block<C> = GenericArray<u8, <C as BlockCipher>::BlockSize>;

#[inline]
fn xor(buf: &mut GenericArray<u8, U16>, key: &GenericArray<u8, U16>) {
  for (a, b) in buf.iter_mut().zip(key) {
    *a ^= *b;
  }
}

/// Multiply by 2 in GF(2**128)
///
/// Based on the IEEE P1619/D11 draft
#[inline]
fn multiply_by_2(out: &mut GenericArray<u8, U16>, input: &GenericArray<u8, U16>) {
  out.iter_mut().zip(input).fold(false, |carry, (o, i)| {
    let (n, overflow) = i.overflowing_mul(2);
    *o = n + carry as u8;
    overflow
  });
  if input[15] >= 128 {
    out[0] ^= 135;
  }
}

#[inline]
fn multiply_by_2_ip(out: &mut GenericArray<u8, U16>) {
  let tmp = *out;
  multiply_by_2(out, &tmp);
}

/// [ECB-Mix-ECB][1] (EME) block cipher mode instance.
///
/// [1]: https://eprint.iacr.org/2003/147.pdf
#[derive(Debug, Clone)]
pub struct Eme<C: BlockCipher + BlockCipher, P: Padding> {
  cipher: C,
  iv: Block<C>,
  _p: PhantomData<P>,
}

impl<C, P> Eme<C, P>
where
  C: BlockCipher<BlockSize = U16> + BlockEncrypt,
  <C as BlockCipher>::ParBlocks: ArrayLength<GenericArray<u8, <C as BlockCipher>::BlockSize>>,
  P: Padding,
{
  fn process_blocks(&self, blocks: &mut [Block<C>], mode: impl Fn(&C, &mut Block<C>)) {
    let l_0 = {
      let mut buf = GenericArray::clone_from_slice(&[0; 16][..]);
      self.cipher.encrypt_block(&mut buf);
      buf
    };
    let mut l = GenericArray::clone_from_slice(&[0; 16][..]);
    multiply_by_2(&mut l, &l_0);

    for block in blocks.iter_mut() {
      xor(block, &l);
      mode(&self.cipher, block); // PPPj = AES-enc(k; PPj)
      multiply_by_2_ip(&mut l);
    }

    let mut mp: Block<C> = GenericArray::clone_from_slice(&self.iv);
    for block in blocks.iter_mut() {
      xor(&mut mp, block);
    }

    let mut m: Block<C> = GenericArray::clone_from_slice(&mp);
    blocks[0].copy_from_slice(&mp); // Store mc in blocks[0]
    mode(&self.cipher, &mut blocks[0]); // mc = AES-enc(k; mp)
    xor(&mut m, &blocks[0]); // m = mp xor mc
    for block in blocks.iter_mut().skip(1) {
      multiply_by_2_ip(&mut m);
      xor(block, &m); // CCCj = 2**(j-1)*m xor PPPj
    }
    xor(&mut blocks[0], &self.iv); // CCC1 = (xorSum CCCj) xor t xor mc

    {
      let (first, rest) = blocks.split_first_mut().unwrap();
      for block in rest.iter_mut() {
        xor(first, block);
      }
    }
    multiply_by_2(&mut l, &l_0); // reset l = 2*AES-enc(k; 0)
    for block in blocks.iter_mut() {
      mode(&self.cipher, block); // CCj = AES-enc(k; CCCj)
      xor(block, &l); // Cj = 2**(j-1)*l xor CCj
      multiply_by_2_ip(&mut l);
    }
  }
}

impl<C, P> BlockMode<C, P> for Eme<C, P>
where
  C: BlockCipher<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
  <C as BlockCipher>::ParBlocks: ArrayLength<GenericArray<u8, <C as BlockCipher>::BlockSize>>,
  P: Padding,
{
  type IvSize = C::BlockSize;

  fn new(cipher: C, iv: &GenericArray<u8, C::BlockSize>) -> Self {
    Self {
      cipher,
      iv: *iv,
      _p: PhantomData::default(),
    }
  }

  fn encrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
    self.process_blocks(blocks, C::encrypt_block);
  }

  fn decrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
    self.process_blocks(blocks, C::decrypt_block);
  }
}
