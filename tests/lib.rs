use aes::Aes256;
use block_modes::BlockMode;
use block_padding::ZeroPadding;
use eme_mode::Eme;

struct EmeTest<'s> {
  encrypt: bool,
  iterations: usize,
  key: &'s [u8],
  iv: &'s [u8],
  input: &'s [u8],
  output: &'s [u8],
}

#[test]
fn eme_16_aes256() {
  eme_test(&EmeTest {
    encrypt: true,
    iterations: 1,
    key: &[0; 32],
    iv: &[0; 16],
    input: &[0; 16],
    output: &[
      0xf1, 0xb9, 0xce, 0x8c, 0xa1, 0x5a, 0x4b, 0xa9, 0xfb, 0x47, 0x69, 0x05, 0x43, 0x4b, 0x9f,
      0xd3,
    ],
  });
}

#[test]
fn eme_512_enc_aes256() {
  // https://web.archive.org/web/20070305060551/http://grouper.ieee.org/groups/1619/email/msg00218.html
  let outputs: Vec<_> = include_bytes!("data/eme-512-aes256-enc.ciphertext.bin")
    .chunks(512)
    .collect();
  let (first, rest) = outputs.split_first().unwrap();

  let mut output = eme_test(&EmeTest {
    encrypt: true,
    iterations: 1,
    key: &[0; 32],
    iv: &[0; 16],
    input: &[0; 512],
    output: first,
  });
  let key = &output[0..32].to_vec();
  for test_output in rest {
    let iv = &output[32..48];
    let input = &output;
    output = eme_test(&EmeTest {
      encrypt: true,
      iterations: 100,
      key,
      iv,
      input,
      output: *test_output,
    });
  }
}

#[test]
fn eme_512_dec_aes256() {
  // https://web.archive.org/web/20070305060551/http://grouper.ieee.org/groups/1619/email/msg00218.html
  let outputs: Vec<_> = include_bytes!("data/eme-512-aes256-dec.ciphertext.bin")
    .chunks(512)
    .collect();
  let (first, rest) = outputs.split_first().unwrap();

  let mut output = eme_test(&EmeTest {
    encrypt: false,
    iterations: 1,
    key: &[0; 32],
    iv: &[0; 16],
    input: &[0; 512],
    output: first,
  });
  let key = &output[0..32].to_vec();
  for test_output in rest {
    let iv = &output[32..48];
    let input = &output;
    output = eme_test(&EmeTest {
      encrypt: false,
      iterations: 100,
      key,
      iv,
      input,
      output: *test_output,
    });
  }
}

#[test]
fn eme_2048_aes256() {
  // https://github.com/rfjakob/eme/blob/v1.1.1/eme_test.go
  eme_test(&EmeTest {
    encrypt: true,
    iterations: 1,
    key: &[0; 32],
    iv: &[0; 16],
    input: &[0; 2048],
    output: include_bytes!("data/eme-2048-aes256.ciphertext.bin"),
  });
}

fn eme_test(test: &EmeTest) -> Vec<u8> {
  let mut pt = test.input.to_vec();
  let n = pt.len();
  for _ in 0..test.iterations {
    let mode = Eme::<Aes256, ZeroPadding>::new_from_slices(test.key, test.iv).unwrap();
    match test.encrypt {
      true => mode.encrypt(&mut pt, n).unwrap(),
      false => mode.decrypt(&mut pt).unwrap(),
    };
  }
  assert_eq!(&pt, &test.output);

  let mut ct = test.output.to_vec();
  for _ in 0..test.iterations {
    let mode = Eme::<Aes256, ZeroPadding>::new_from_slices(test.key, test.iv).unwrap();
    match test.encrypt {
      true => mode.decrypt(&mut ct).unwrap(),
      false => mode.encrypt(&mut ct, n).unwrap(),
    };
  }
  assert_eq!(&ct, &test.input);

  pt
}
