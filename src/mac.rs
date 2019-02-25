use crate::rng::SecKeyGen;
use std::error::Error;


/// Information about a MAC implementation
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct MacInfo {
	/// The name
	pub name: &'static str,
	
	/// The MAC length
	pub mac_len: usize,
	
	/// The minimum supported key length
	pub key_len_min: usize,
	/// The maximum supported key length
	pub key_len_max: usize
}


/// A stateless (oneshot) MAC interface
pub trait Mac: SecKeyGen {
	/// Returns information about the MAC
	fn info(&self) -> MacInfo;
	
	/// Authenticates `data` into `buf` using `key` and returns the MAC length
	fn authenticate(&self, buf: &mut[u8], data: &[u8], key: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}


/// A stateful (streaming) MAC interface
pub trait StreamingMac: SecKeyGen {
	/// Returns information about the MAC
	fn info(&self) -> MacInfo;
	
	/// (Re-)initializes the MAC state with `key`
	fn init(&mut self, key: &[u8]) -> Result<(), Box<dyn Error + 'static>>;
	/// Adds the data in `input` to the MAC state
	fn update<'a>(&mut self, data: impl Iterator<Item = &'a u8>) -> Result<(), Box<dyn Error + 'static>>;
	/// Computes the MAC into `buf` and returns the MAC length
	fn finish(&mut self, buf: &mut[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}