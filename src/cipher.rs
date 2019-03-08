use crate::rng::SecKeyGen;
use std::{ error::Error, io::Write };


/// Information about a cipher implementation
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct CipherInfo {
	/// The name
	pub name: &'static str,
	
	/// The key length
	pub key_len: usize,
	/// The nonce length
	pub nonce_len: usize,
	
	/// The AEAD tag length if the cipher is an AEAD cipher
	pub aead_tag_len: Option<usize>
}


/// A stateless (oneshot) cipher interface
pub trait Cipher: SecKeyGen {
	/// Returns information about the cipher
	fn info(&self) -> CipherInfo;
	
	/// Predicts the _maximum_ encrypted length for `plaintext_len` bytes
	fn encrypted_len_max(&self, plaintext_len: usize) -> usize;
	
	/// Encrypts `plaintext_len` bytes in-place in `buf` using `key` and `nonce` and returns the
	/// ciphertext length
	fn encrypt(&self, buf: &mut[u8], plaintext_len: usize, key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>;
	/// Encrypts `plaintext` into `buf` using `key` and `nonce` and returns the ciphertext length
	fn encrypt_to(&self, buf: &mut[u8], plaintext: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>;
	
	/// Decrypts `ciphertext_len` bytes in-place in `buf` using `key` and `nonce` and returns the
	/// plaintext length
	fn decrypt(&self, buf: &mut[u8], ciphertext_len: usize, key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>;
	/// Decrypts `ciphertext` into `buf` using `key` and `nonce` and returns the plaintext length
	fn decrypt_to(&self, buf: &mut[u8], ciphertext: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>;
}

/// An AEAD extension for `Cipher`
pub trait AeadCipher: Cipher {
	/// AEAD-seals `plaintext_len` bytes in-place in `buf` together with `ad` using `key` and
	/// `nonce` and returns the ciphertext length
	fn seal(&self, buf: &mut[u8], plaintext_len: usize, ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>;
	/// AEAD-seals `plaintext` into `buf` together with `ad` using `key` and `nonce` and returns the
	/// ciphertext length
	fn seal_to(&self, buf: &mut[u8], plaintext: &[u8], ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>;
	
	/// AEAD-opens `ciphertext_len` bytes in-place in `buf` together with `ad` using `key` and
	/// `nonce` and returns the plaintext length
	fn open(&self, buf: &mut[u8], ciphertext_len: usize, ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>;
	/// AEAD-opens `ciphertext` into `buf` together with `ad` using `key` and `nonce` and returns
	/// the plaintext length
	fn open_to(&self, buf: &mut[u8], ciphertext: &[u8], ad: &[u8], key: &[u8], nonce: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>;
}


/// A stateful (streaming) cipher interface
pub trait StreamingCipher: SecKeyGen {
	/// Returns information about the cipher
	fn info(&self) -> CipherInfo;
	
	/// (Re-)initializes the handle with `key` and `nonce`
	fn init(&mut self, key: &[u8], nonce: &[u8]) -> Result<(), Box<dyn Error + 'static>>;
	/// Processes the bytes in `input` and writes the resulting bytes to `output` and returns the
	/// amount of bytes written
	fn update(&mut self, input: &[u8], output: impl Write)
		-> Result<usize, Box<dyn Error + 'static>>;
	/// Finishes the operation and writes the pending bytes to `output` and returns the amount of
	/// bytes written
	fn finish(&mut self, output: impl Write) -> Result<usize, Box<dyn Error + 'static>>;
}

/// An AEAD extension for `StreamingCipher`
pub trait StreamingAeadCipher: StreamingCipher {
	/// Adds the additional data in `ad_input` to the AEAD state
	fn update_ad<'a>(&mut self, ad_input: &[u8]) -> Result<(), Box<dyn Error + 'static>>;
}