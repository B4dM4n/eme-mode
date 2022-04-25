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

use cipher::{
  consts::{True, U1, U16, U2048},
  crypto_common::{InnerUser, IvSizeUser},
  generic_array::{ArrayLength, GenericArray},
  inout::InOut,
  typenum::{IsLessOrEqual, PartialDiv},
  AlgorithmName, Block, BlockBackend, BlockCipher, BlockClosure, BlockDecryptMut, BlockEncryptMut,
  BlockSizeUser, InnerIvInit, Iv, IvState, ParBlocksSizeUser,
};
use core::{fmt, marker::PhantomData};

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
