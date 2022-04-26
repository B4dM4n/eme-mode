#![warn(
  clippy::cargo,
  clippy::nursery,
  clippy::pedantic,
  missing_debug_implementations,
  missing_docs,
  rust_2018_idioms
)]
#![deny(unsafe_code)]
#![allow(clippy::inline_always)]
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! [ECB-Mix-ECB][1] (EME) block cipher mode implementation.
//!
//! # Usage example
//! ```
//! use aes::Aes128;
//! use eme_mode::{
//!   cipher::{block_padding::Pkcs7, consts::U16, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
//!   Eme,
//! };
//!
//! type Aes128Eme = Eme<Aes128, U16>;
//!
//! let key = [0; 16];
//! let iv = [1; 16];
//! let plaintext = b"Hello world!";
//! let mut cipher = Aes128Eme::new_from_slices(&key, &iv).unwrap();
//!
//! // buffer must have enough space for message+padding
//! let mut buffer = [0u8; 16];
//! // copy message to the buffer
//! let pos = plaintext.len();
//! buffer[..pos].copy_from_slice(plaintext);
//! cipher.encrypt_padded_mut::<Pkcs7>(buffer.as_mut_slice().into(), pos);
//!
//! assert_eq!(
//!   buffer,
//!   [147, 227, 119, 228, 187, 150, 249, 88, 176, 145, 53, 209, 217, 99, 70, 245]
//! );
//!
//! // re-create cipher mode instance
//! let mut cipher = Aes128Eme::new_from_slices(&key, &iv).unwrap();
//! let decrypted = cipher
//!   .decrypt_padded_mut::<Pkcs7>(buffer.as_mut_slice().into())
//!   .unwrap();
//!
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! [1]: https://eprint.iacr.org/2003/147.pdf

#[cfg(all(feature = "block-padding", feature = "alloc"))]
extern crate alloc;

use cipher::{
  consts::{True, U1, U16, U2048},
  crypto_common::{InnerUser, IvSizeUser},
  generic_array::{ArrayLength, GenericArray},
  inout::{InOut, InOutBuf},
  typenum::{IsLessOrEqual, PartialDiv},
  AlgorithmName, Block, BlockBackend, BlockCipher, BlockClosure, BlockDecryptMut, BlockEncryptMut,
  BlockSizeUser, InnerIvInit, Iv, IvState, ParBlocksSizeUser,
};
use core::{fmt, marker::PhantomData};

#[cfg(all(feature = "block-padding", feature = "alloc"))]
use alloc::{vec, vec::Vec};

#[cfg(all(feature = "block-padding", feature = "alloc"))]
use cipher::Unsigned;

#[cfg(feature = "block-padding")]
use cipher::{
  block_padding::{Padding, UnpadError},
  inout::{InOutBufReserved, PadError, PaddedInOutBuf},
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

pub use cipher;

#[inline(always)]
fn xor<N: ArrayLength<u8>>(out: &mut GenericArray<u8, N>, buf: &GenericArray<u8, N>) {
  for (a, b) in out.iter_mut().zip(buf) {
    *a ^= *b;
  }
}

/// Multiply by 2 in GF(2**128)
///
/// Based on the IEEE P1619/D11 draft
#[inline(always)]
fn multiply_by_2(out: &mut GenericArray<u8, U16>, input: &GenericArray<u8, U16>) {
  out.iter_mut().zip(input).fold(false, |carry, (o, i)| {
    let (n, overflow) = i.overflowing_mul(2);
    *o = n + u8::from(carry);
    overflow
  });
  if input[15] >= 128 {
    out[0] ^= 135;
  }
}

#[inline(always)]
fn multiply_by_2_ip(out: &mut GenericArray<u8, U16>) {
  let tmp = *out;
  multiply_by_2(out, &tmp);
}

/// [ECB-Mix-ECB][1] (EME) block mode instance.
///
/// The `BlockSize` of this instance can be chosen between 16 and 2048 bytes and
/// must be divisible by 16.
///
/// [1]: https://eprint.iacr.org/2003/147.pdf
#[derive(Clone)]
pub struct Eme<C: BlockCipher, BS> {
  cipher: C,
  t: Block<C>,
  _bs: PhantomData<BS>,
}

impl<C, BS> BlockSizeUser for Eme<C, BS>
where
  C: BlockCipher,
  BS: ArrayLength<u8> + PartialDiv<U16> + IsLessOrEqual<U2048, Output = True>,
{
  type BlockSize = BS;
}

impl<C, BS> BlockEncryptMut for Eme<C, BS>
where
  C: BlockEncryptMut + BlockCipher + BlockSizeUser<BlockSize = U16>,
  BS: ArrayLength<u8> + PartialDiv<U16> + IsLessOrEqual<U2048, Output = True>,
{
  fn encrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
    let Self { cipher, t, _bs } = self;
    let mut l0 = GenericArray::default();
    cipher.encrypt_block_mut(&mut l0);
    cipher.encrypt_with_backend_mut(Closure { t, l0, f });
  }
}

impl<C, BS> BlockDecryptMut for Eme<C, BS>
where
  C: BlockEncryptMut + BlockDecryptMut + BlockCipher + BlockSizeUser<BlockSize = U16>,
  BS: ArrayLength<u8> + PartialDiv<U16> + IsLessOrEqual<U2048, Output = True>,
{
  fn decrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
    let Self { cipher, t, _bs } = self;
    let mut l0 = GenericArray::default();
    cipher.encrypt_block_mut(&mut l0);
    cipher.decrypt_with_backend_mut(Closure { t, l0, f });
  }
}

impl<C, BS> InnerUser for Eme<C, BS>
where
  C: BlockCipher + BlockSizeUser<BlockSize = U16>,
{
  type Inner = C;
}

impl<C, BS> IvSizeUser for Eme<C, BS>
where
  C: BlockCipher + BlockSizeUser<BlockSize = U16>,
{
  type IvSize = U16;
}

impl<C, BS> InnerIvInit for Eme<C, BS>
where
  C: BlockCipher + BlockSizeUser<BlockSize = U16>,
{
  #[inline]
  fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
    Self {
      cipher,
      t: *iv,
      _bs: PhantomData,
    }
  }
}

impl<C, BS> IvState for Eme<C, BS>
where
  C: BlockCipher + BlockSizeUser<BlockSize = U16>,
{
  #[inline]
  fn iv_state(&self) -> Iv<Self> {
    self.t
  }
}

impl<C, BS> AlgorithmName for Eme<C, BS>
where
  C: BlockCipher + BlockSizeUser<BlockSize = U16> + AlgorithmName,
{
  fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("eme_mode::Eme<")?;
    <C as AlgorithmName>::write_alg_name(f)?;
    f.write_str(">")
  }
}

impl<C, BS> fmt::Debug for Eme<C, BS>
where
  C: BlockCipher + BlockSizeUser<BlockSize = U16> + AlgorithmName,
{
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("eme_mode::Eme<")?;
    <C as AlgorithmName>::write_alg_name(f)?;
    f.write_str("> { ... }")
  }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockCipher, BS> Drop for Eme<C, BS> {
  fn drop(&mut self) {
    self.t.zeroize();
  }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockCipher + ZeroizeOnDrop, BS> ZeroizeOnDrop for Eme<C, BS> {}

struct Closure<'a, BS, BC>
where
  BC: BlockClosure<BlockSize = BS>,
{
  t: &'a mut GenericArray<u8, U16>,
  l0: GenericArray<u8, U16>,
  f: BC,
}

impl<'a, BS, BC> BlockSizeUser for Closure<'a, BS, BC>
where
  BS: ArrayLength<u8>,
  BC: BlockClosure<BlockSize = BS>,
{
  type BlockSize = U16;
}

impl<'a, BS, BC> BlockClosure for Closure<'a, BS, BC>
where
  BS: ArrayLength<u8>,
  BC: BlockClosure<BlockSize = BS>,
{
  #[inline]
  fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
    let Self { t, l0, f } = self;
    f.call(&mut Backend {
      t,
      l0,
      backend,
      _bs: PhantomData,
    });
  }
}

struct Backend<'a, BS, BK>
where
  BS: ArrayLength<u8>,
  BK: BlockBackend<BlockSize = U16>,
{
  t: &'a mut GenericArray<u8, U16>,
  l0: GenericArray<u8, U16>,
  backend: &'a mut BK,
  _bs: PhantomData<BS>,
}

impl<'a, BS, BK> BlockSizeUser for Backend<'a, BS, BK>
where
  BS: ArrayLength<u8>,
  BK: BlockBackend<BlockSize = U16>,
{
  type BlockSize = BS;
}

impl<'a, BS, BK> ParBlocksSizeUser for Backend<'a, BS, BK>
where
  BS: ArrayLength<u8>,
  BK: BlockBackend<BlockSize = U16>,
{
  type ParBlocksSize = U1;
}

impl<'a, BS, BK> BlockBackend for Backend<'a, BS, BK>
where
  BS: ArrayLength<u8>,
  BK: BlockBackend<BlockSize = U16>,
{
  #[inline]
  fn proc_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
    let Self {
      t,
      l0,
      backend,
      _bs,
    } = self;
    let mut l = GenericArray::default();
    multiply_by_2(&mut l, l0);

    let (mut chunks, rest) = block.into_buf().into_chunks::<U16>();
    assert!(rest.is_empty());

    for i in 0..(chunks.get_in().len()) {
      let mut block = chunks.get(i);
      block.xor_in2out(&l);
      backend.proc_block(block.get_out().into()); // PPPj = AES-enc(k; PPj)
      multiply_by_2_ip(&mut l);
    }

    let mut mp = GenericArray::clone_from_slice(t);
    for i in 0..(chunks.get_in().len()) {
      let mut block = chunks.get(i);

      xor(&mut mp, block.get_out());
    }

    let mut m = GenericArray::clone_from_slice(&mp);
    let mut block0 = GenericArray::clone_from_slice(&mp);
    backend.proc_block((&mut block0).into()); // mc = AES-enc(k; mp)
    xor(&mut m, &block0); // m = mp xor mc
    for i in 1..(chunks.get_in().len()) {
      let mut block = chunks.get(i);
      multiply_by_2_ip(&mut m);
      xor(block.get_out(), &m); // CCCj = 2**(j-1)*m xor PPPj
    }
    xor(&mut block0, t); // CCC1 = (xorSum CCCj) xor t xor mc

    for i in 1..(chunks.get_in().len()) {
      xor(&mut block0, chunks.get(i).get_out());
    }
    chunks.get(0).get_out().copy_from_slice(&block0);
    multiply_by_2(&mut l, l0); // reset l = 2*AES-enc(k; 0)

    for i in 0..(chunks.get_in().len()) {
      let mut block = chunks.get(i);
      backend.proc_block(block.get_out().into()); // CCj = AES-enc(k; CCCj)
      xor(block.get_out(), &l); // Cj = 2**(j-1)*l xor CCj
      multiply_by_2_ip(&mut l);
    }
  }
}

/// EME block mode instance with dynamic block size.
///
/// There is no fixed `BlockSize` for this mode. The `BlockSize` is determined
/// by the length of the given input, which must be between 16 and 2048 bytes
/// and also divisible by 16.
///
/// [1]: https://eprint.iacr.org/2003/147.pdf
#[derive(Clone)]
pub struct DynamicEme<C: BlockCipher> {
  cipher: C,
  tweak: Block<C>,
}

impl<C: BlockEncryptMut + BlockCipher + BlockSizeUser<BlockSize = U16>> DynamicEme<C> {
  /// Encrypt block in-place.
  ///
  /// # Panics
  ///
  /// - When `block` length is greater than 2048
  /// - When `block` length is not divisible by 16
  pub fn encrypt_block_mut(&mut self, block: &mut [u8]) {
    let (chunks, rest) = InOutBuf::from(block).into_chunks();
    assert!(rest.is_empty());
    self.encrypt_blocks_inout_mut(chunks);
  }

  /// Encrypt chunks in-place.
  ///
  /// # Panics
  ///
  /// - When `chunks` length is greater than 128 blocks (2048 bytes)
  pub fn encrypt_blocks_inout_mut(&mut self, mut chunks: InOutBuf<'_, '_, Block<C>>) {
    assert!(chunks.len() <= 128);
    if chunks.is_empty() {
      return;
    }

    let mut l0 = GenericArray::default();
    self.cipher.encrypt_block_mut(&mut l0);

    let mut l = GenericArray::default();
    multiply_by_2(&mut l, &l0);

    for i in 0..(chunks.get_in().len()) {
      let mut block = chunks.get(i);
      block.xor_in2out(&l);
      self.cipher.encrypt_block_mut(block.get_out()); // PPPj = AES-enc(k; PPj)
      multiply_by_2_ip(&mut l);
    }

    let mut mp = GenericArray::clone_from_slice(&self.tweak);
    for i in 0..(chunks.get_in().len()) {
      let mut block = chunks.get(i);

      xor(&mut mp, block.get_out());
    }

    let mut m = GenericArray::clone_from_slice(&mp);
    let mut block0 = GenericArray::clone_from_slice(&mp);
    self.cipher.encrypt_block_mut(&mut block0); // mc = AES-enc(k; mp)
    xor(&mut m, &block0); // m = mp xor mc
    for i in 1..(chunks.get_in().len()) {
      let mut block = chunks.get(i);
      multiply_by_2_ip(&mut m);
      xor(block.get_out(), &m); // CCCj = 2**(j-1)*m xor PPPj
    }
    xor(&mut block0, &self.tweak); // CCC1 = (xorSum CCCj) xor t xor mc

    for i in 1..(chunks.get_in().len()) {
      xor(&mut block0, chunks.get(i).get_out());
    }
    chunks.get(0).get_out().copy_from_slice(&block0);
    multiply_by_2(&mut l, &l0); // reset l = 2*AES-enc(k; 0)

    for i in 0..(chunks.get_in().len()) {
      let mut block = chunks.get(i);
      self.cipher.encrypt_block_mut(block.get_out()); // CCj = AES-enc(k; CCCj)
      xor(block.get_out(), &l); // Cj = 2**(j-1)*l xor CCj
      multiply_by_2_ip(&mut l);
    }
  }

  /// Encrypt blocks in-place.
  ///
  /// # Panics
  ///
  /// - When `blocks` length is greater than 128 blocks (2048 bytes)
  #[inline]
  pub fn encrypt_blocks_mut(&mut self, blocks: &mut [Block<C>]) {
    self.encrypt_blocks_inout_mut(blocks.into());
  }

  /// Pad input and encrypt. Returns resulting ciphertext slice.
  ///
  /// # Errors
  ///
  /// Returns [`PadError`] if length of output buffer is not sufficient.
  ///
  /// # Panics
  ///
  /// - When `data` length + padding is greater than 2048 bytes
  #[cfg(feature = "block-padding")]
  #[cfg_attr(docsrs, doc(cfg(feature = "block-padding")))]
  #[inline]
  pub fn encrypt_padded_inout_mut<'inp, 'out, P: Padding<C::BlockSize>>(
    &mut self,
    data: InOutBufReserved<'inp, 'out, u8>,
  ) -> Result<&'out [u8], PadError> {
    let mut buf = padded_in_out_buf_to_in_out_buf(data.into_padded_blocks::<P, C::BlockSize>()?);

    self.encrypt_blocks_inout_mut(buf.reborrow());
    Ok(chunks_into_out(buf))
  }

  /// Pad input and encrypt in-place. Returns resulting ciphertext slice.
  ///
  /// # Errors
  ///
  /// Returns [`PadError`] if length of output buffer is not sufficient.
  ///
  /// # Panics
  ///
  /// - When `buf` length + padding is greater than 2048 bytes
  #[cfg(feature = "block-padding")]
  #[cfg_attr(docsrs, doc(cfg(feature = "block-padding")))]
  #[inline]
  pub fn encrypt_padded_mut<'b, P: Padding<C::BlockSize>>(
    &mut self,
    buf: &'b mut [u8],
    msg_len: usize,
  ) -> Result<&'b [u8], PadError> {
    let buf = InOutBufReserved::from_mut_slice(buf, msg_len).map_err(|_| PadError)?;
    self.encrypt_padded_inout_mut::<P>(buf)
  }

  /// Pad input and encrypt buffer-to-buffer. Returns resulting ciphertext
  /// slice.
  ///
  /// # Errors
  ///
  /// Returns [`PadError`] if length of output buffer is not sufficient.
  ///
  /// # Panics
  ///
  /// - When `msg` length + padding is greater than 2048 bytes
  #[cfg(feature = "block-padding")]
  #[cfg_attr(docsrs, doc(cfg(feature = "block-padding")))]
  #[inline]
  pub fn encrypt_padded_b2b_mut<'a, P: Padding<C::BlockSize>>(
    &mut self,
    msg: &[u8],
    out_buf: &'a mut [u8],
  ) -> Result<&'a [u8], PadError> {
    let buf = InOutBufReserved::from_slices(msg, out_buf).map_err(|_| PadError)?;
    self.encrypt_padded_inout_mut::<P>(buf)
  }

  /// Pad input and encrypt into a newly allocated Vec. Returns resulting
  /// ciphertext Vec.
  ///
  /// # Panics
  ///
  /// - When `msg` length + padding is greater than 2048 bytes
  #[cfg(all(feature = "block-padding", feature = "alloc"))]
  #[cfg_attr(docsrs, doc(cfg(all(feature = "block-padding", feature = "alloc"))))]
  #[inline]
  pub fn encrypt_padded_vec_mut<P: Padding<C::BlockSize>>(&mut self, msg: &[u8]) -> Vec<u8> {
    let mut out = allocate_out_vec::<C>(msg.len());
    let len = self
      .encrypt_padded_b2b_mut::<P>(msg, &mut out)
      .expect("enough space for encrypting is allocated")
      .len();
    out.truncate(len);
    out
  }
}

impl<C: BlockEncryptMut + BlockDecryptMut + BlockCipher + BlockSizeUser<BlockSize = U16>>
  DynamicEme<C>
{
  /// Decrypt block in-place.
  ///
  /// # Panics
  ///
  /// - When `block` length is greater than 2048
  /// - When `block` length is not divisible by 16
  pub fn decrypt_block_mut(&mut self, block: &mut [u8]) {
    let (chunks, rest) = InOutBuf::from(block).into_chunks();
    assert!(rest.is_empty());
    self.decrypt_blocks_inout_mut(chunks);
  }

  /// Decrypt chunks in-place.
  ///
  /// # Panics
  ///
  /// - When `chunks` length is greater than 128 blocks (2048 bytes)
  pub fn decrypt_blocks_inout_mut(&mut self, mut chunks: InOutBuf<'_, '_, Block<C>>) {
    assert!(chunks.len() <= 128);
    if chunks.is_empty() {
      return;
    }

    let mut l0 = GenericArray::default();
    self.cipher.encrypt_block_mut(&mut l0);

    let mut l = GenericArray::default();
    multiply_by_2(&mut l, &l0);

    for i in 0..(chunks.get_in().len()) {
      let mut block = chunks.get(i);
      block.xor_in2out(&l);
      self.cipher.decrypt_block_mut(block.get_out()); // PPPj = AES-enc(k; PPj)
      multiply_by_2_ip(&mut l);
    }

    let mut mp = GenericArray::clone_from_slice(&self.tweak);
    for i in 0..(chunks.get_in().len()) {
      let mut block = chunks.get(i);

      xor(&mut mp, block.get_out());
    }

    let mut m = GenericArray::clone_from_slice(&mp);
    let mut block0 = GenericArray::clone_from_slice(&mp);
    self.cipher.decrypt_block_mut(&mut block0); // mc = AES-enc(k; mp)
    xor(&mut m, &block0); // m = mp xor mc
    for i in 1..(chunks.get_in().len()) {
      let mut block = chunks.get(i);
      multiply_by_2_ip(&mut m);
      xor(block.get_out(), &m); // CCCj = 2**(j-1)*m xor PPPj
    }
    xor(&mut block0, &self.tweak); // CCC1 = (xorSum CCCj) xor t xor mc

    for i in 1..(chunks.get_in().len()) {
      xor(&mut block0, chunks.get(i).get_out());
    }
    chunks.get(0).get_out().copy_from_slice(&block0);
    multiply_by_2(&mut l, &l0); // reset l = 2*AES-enc(k; 0)

    for i in 0..(chunks.get_in().len()) {
      let mut block = chunks.get(i);
      self.cipher.decrypt_block_mut(block.get_out()); // CCj = AES-enc(k; CCCj)
      xor(block.get_out(), &l); // Cj = 2**(j-1)*l xor CCj
      multiply_by_2_ip(&mut l);
    }
  }

  /// Decrypt blocks in-place.
  ///
  /// # Panics
  ///
  /// - When `blocks` length is greater than 128 blocks (2048 bytes)
  #[inline]
  pub fn decrypt_blocks_mut(&mut self, blocks: &mut [Block<C>]) {
    self.decrypt_blocks_inout_mut(blocks.into());
  }

  /// Decrypt input and unpad it. Returns resulting ciphertext slice.
  ///
  /// # Errors
  ///
  /// Returns [`UnpadError`] if padding is malformed or if input length is
  /// not multiple of `C::BlockSize`.
  ///
  /// # Panics
  ///
  /// - When `data` length is greater than 2048
  /// - When `data` length is not divisible by 16
  #[cfg(feature = "block-padding")]
  #[cfg_attr(docsrs, doc(cfg(feature = "block-padding")))]
  #[inline]
  pub fn decrypt_padded_inout_mut<'inp, 'out, P: Padding<C::BlockSize>>(
    mut self,
    data: InOutBuf<'inp, 'out, u8>,
  ) -> Result<&'out [u8], UnpadError> {
    let (mut blocks, tail) = data.into_chunks();
    if !tail.is_empty() {
      return Err(UnpadError);
    }
    self.decrypt_blocks_inout_mut(blocks.reborrow());
    P::unpad_blocks(blocks.into_out())
  }

  /// Decrypt input and unpad it in-place. Returns resulting ciphertext slice.
  ///
  /// # Errors
  ///
  /// Returns [`UnpadError`] if padding is malformed or if input length is
  /// not multiple of `C::BlockSize`.
  ///
  /// # Panics
  ///
  /// - When `buf` length is greater than 2048
  /// - When `buf` length is not divisible by 16
  #[cfg(feature = "block-padding")]
  #[cfg_attr(docsrs, doc(cfg(feature = "block-padding")))]
  #[inline]
  pub fn decrypt_padded_mut<P: Padding<C::BlockSize>>(
    self,
    buf: &mut [u8],
  ) -> Result<&[u8], UnpadError> {
    self.decrypt_padded_inout_mut::<P>(buf.into())
  }

  /// Decrypt input and unpad it buffer-to-buffer. Returns resulting
  /// ciphertext slice.
  ///
  /// # Errors
  ///
  /// Returns [`UnpadError`] if padding is malformed or if input length is
  /// not multiple of `C::BlockSize`.
  ///
  /// # Panics
  ///
  /// - When `in_buf` length is greater than 2048
  /// - When `in_buf` length is not divisible by 16
  #[cfg(feature = "block-padding")]
  #[cfg_attr(docsrs, doc(cfg(feature = "block-padding")))]
  #[inline]
  pub fn decrypt_padded_b2b_mut<'a, P: Padding<C::BlockSize>>(
    self,
    in_buf: &[u8],
    out_buf: &'a mut [u8],
  ) -> Result<&'a [u8], UnpadError> {
    if out_buf.len() < in_buf.len() {
      return Err(UnpadError);
    }
    let n = in_buf.len();
    // note: `new` always returns `Ok` here
    let buf = InOutBuf::new(in_buf, &mut out_buf[..n]).map_err(|_| UnpadError)?;
    self.decrypt_padded_inout_mut::<P>(buf)
  }

  /// Decrypt input and unpad it in a newly allocated Vec. Returns resulting
  /// ciphertext Vec.
  ///
  /// # Errors
  ///
  /// Returns [`UnpadError`] if padding is malformed or if input length is
  /// not multiple of `C::BlockSize`.
  ///
  /// # Panics
  ///
  /// - When `buf` length is greater than 2048
  /// - When `buf` length is not divisible by 16
  #[cfg(all(feature = "block-padding", feature = "alloc"))]
  #[cfg_attr(docsrs, doc(cfg(all(feature = "block-padding", feature = "alloc"))))]
  #[inline]
  pub fn decrypt_padded_vec_mut<P: Padding<C::BlockSize>>(
    self,
    buf: &[u8],
  ) -> Result<Vec<u8>, UnpadError> {
    let mut out = vec![0; buf.len()];
    let len = self.decrypt_padded_b2b_mut::<P>(buf, &mut out)?.len();
    out.truncate(len);
    Ok(out)
  }
}

impl<C> InnerUser for DynamicEme<C>
where
  C: BlockCipher + BlockSizeUser<BlockSize = U16>,
{
  type Inner = C;
}

impl<C> IvSizeUser for DynamicEme<C>
where
  C: BlockCipher + BlockSizeUser<BlockSize = U16>,
{
  type IvSize = U16;
}

impl<C> InnerIvInit for DynamicEme<C>
where
  C: BlockCipher + BlockSizeUser<BlockSize = U16>,
{
  #[inline]
  fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
    Self { cipher, tweak: *iv }
  }
}

impl<C> IvState for DynamicEme<C>
where
  C: BlockCipher + BlockSizeUser<BlockSize = U16>,
{
  #[inline]
  fn iv_state(&self) -> Iv<Self> {
    self.tweak
  }
}

impl<C> AlgorithmName for DynamicEme<C>
where
  C: BlockCipher + BlockSizeUser<BlockSize = U16> + AlgorithmName,
{
  fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("eme_mode::DynamicEme<")?;
    <C as AlgorithmName>::write_alg_name(f)?;
    f.write_str(">")
  }
}

impl<C> fmt::Debug for DynamicEme<C>
where
  C: BlockCipher + BlockSizeUser<BlockSize = U16> + AlgorithmName,
{
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("eme_mode::DynamicEme<")?;
    <C as AlgorithmName>::write_alg_name(f)?;
    f.write_str("> { ... }")
  }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockCipher> Drop for DynamicEme<C> {
  fn drop(&mut self) {
    self.tweak.zeroize();
  }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockCipher + ZeroizeOnDrop> ZeroizeOnDrop for DynamicEme<C> {}

#[cfg(feature = "block-padding")]
#[allow(unsafe_code)]
fn padded_in_out_buf_to_in_out_buf<'inp, 'out, BS: ArrayLength<u8>>(
  mut buf: PaddedInOutBuf<'inp, 'out, BS>,
) -> InOutBuf<'out, 'out, GenericArray<u8, BS>> {
  let blocks = buf.get_blocks();
  let mut blocks_len = blocks.len();
  let (blocks_in, blocks_out) = blocks.into_raw();

  if blocks_in != blocks_out {
    // SAFETY: `blocks_in` and `blocks_out` point to at least `blcoks_len` elements,
    // which is checked by InOutBuf
    unsafe {
      core::ptr::copy_nonoverlapping(blocks_in, blocks_out, blocks_len);
    }
  }

  if let Some(tail) = buf.get_tail_block() {
    let (tail_in, tail_out) = tail.into_raw();

    // SAFETY: `tail_in` is in the stack allocated PaddedInOutBuf and `tail_out` is
    // ensured by into_padded_blocks to fit in `blocks_out`
    unsafe {
      assert_eq!(blocks_out.add(blocks_len), tail_out);
      core::ptr::copy_nonoverlapping(tail_in, tail_out, 1);
      blocks_len += 1;
    }
  }

  // SAFETY: `blocks_out` is obtained from a `PaddedInOutBuf`, which is checked to
  // be valid at construction time
  unsafe { InOutBuf::from_raw(blocks_out, blocks_out, blocks_len) }
}

#[cfg(feature = "block-padding")]
#[allow(unsafe_code)]
fn chunks_into_out<'inp, 'out, BS: ArrayLength<u8>>(
  buf: InOutBuf<'inp, 'out, GenericArray<u8, BS>>,
) -> &'out [u8] {
  let total_blocks = buf.len();
  let res_len = BS::USIZE * total_blocks;
  let (_, out_ptr) = buf.into_raw();

  // SAFETY: `res_len` is always valid for the output buffer since
  // it's checked during InOutBuf type construction
  unsafe { core::slice::from_raw_parts(out_ptr as *const u8, res_len) }
}

#[cfg(all(feature = "block-padding", feature = "alloc"))]
fn allocate_out_vec<BS: BlockSizeUser>(len: usize) -> Vec<u8> {
  let bs = BS::BlockSize::USIZE;
  vec![0; bs * (len / bs + 1)]
}
