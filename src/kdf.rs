use std::error::Error;


/// Information about a KDF implementation
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct KdfInfo {
	/// The name
	pub name: &'static str,
	
	/// The minimum output length
	pub output_len_min: usize,
	/// The maximum output length
	pub output_len_max: usize,
	
	/// The minimum supported key length
	pub key_len_min: usize,
	/// The maximum supported key length
	pub key_len_max: usize
}


/// A stateless (oneshot) key derivation interface
pub trait Kdf {
	/// Returns information about the MAC
	fn info(&self) -> KdfInfo;
	
	/// Fills `buf` with key bytes derived from `base_key` and `salt`
	fn derive(&self, buf: &mut[u8], base_key: &[u8], salt: &[u8])
		-> Result<(), Box<dyn Error + 'static>>;
}