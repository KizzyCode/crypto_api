use ::std::error::Error;


/// Information about a cipher implementation
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct CipherInfo {
	/// The name
	pub name: &'static str,
	
	/// The key length
	pub key_len: usize,
	/// The nonce length
	pub nonce_len: usize
}


/// A stateless (oneshot) cipher interface
pub trait Cipher {
	/// Returns information about the cipher
	fn info(&self) -> CipherInfo;
	
	/// Predicts the _maximum_ encrypted length for `plaintext_len` bytes
	fn encrypted_len_max(&self, plaintext_len: usize) -> usize;
	
	/// Encrypts `plaintext_len` bytes in-place in `buf` using `key` and `nonce` and returns the
	/// ciphertext length
	fn encrypt(&self, buf: impl AsMut<[u8]>, plaintext_len: usize, key: impl AsRef<[u8]>,
		nonce: impl AsRef<[u8]>) -> Result<usize, Box<Error>>;
	
	/// Decrypts `ciphertext_len` bytes in-place in `buf` using `key` and `nonce` and returns the
	/// plaintext length
	fn decrypt(&self, buf: impl AsMut<[u8]>, ciphertext_len: usize, key: impl AsRef<[u8]>,
		nonce: impl AsRef<[u8]>) -> Result<usize, Box<Error>>;
}

/// An AEAD extension for `Cipher`
pub trait AeadCipher: Cipher {
	/// AEAD-seals `plaintext_len` bytes in-place in `buf` together with `ad` using `key` and
	/// `nonce` and returns the ciphertext length
	fn seal(&self, buf: impl AsMut<[u8]>, plaintext_len: usize, ad: impl AsRef<[u8]>,
		key: impl AsRef<[u8]>, nonce: impl AsRef<[u8]>) -> Result<usize, Box<Error>>;
	
	/// AEAD-opens `ciphertext_len` bytes in-place in `buf` together with `ad` using `key` and
	/// `nonce` and returns the plaintext length
	fn open(&self, buf: impl AsMut<[u8]>, ciphertext_len: usize, ad: impl AsRef<[u8]>,
		key: impl AsRef<[u8]>, nonce: impl AsRef<[u8]>) -> Result<usize, Box<Error>>;
}


/// A stateful (streaming) cipher interface
pub trait StreamingCipher {
	/// Returns information about the cipher
	fn info(&self) -> CipherInfo;
	
	/// (Re-)initializes the handle with `key` and `nonce`
	fn init(&mut self, key: impl AsRef<[u8]>, nonce: impl AsRef<[u8]>) -> Result<(), Box<Error>>;
	
	/// Processes the bytes in `input` and writes the resulting bytes to `output` and returns the
	/// amount of bytes written
	fn update<'a>(&mut self, input: impl Iterator<Item = &'a u8>,
		output: impl Iterator<Item = &'a mut u8>) -> Result<usize, Box<Error>>;
	
	/// Finishes the operation and writes the pending bytes to `output` and returns the amount of
	/// bytes written
	fn finish<'a>(&mut self, output: impl Iterator<Item = &'a mut u8>) -> Result<usize, Box<Error>>;
}

/// An AEAD extension for `StreamingCipher`
pub trait StreamingAeadCipher: StreamingCipher {
	/// Adds the additional data in `ad_input` to the AEAD state
	fn update_ad<'a>(&mut self, ad_input: impl Iterator<Item = &'a u8>) -> Result<(), Box<Error>>;
}