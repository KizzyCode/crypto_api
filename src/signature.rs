use std::error::Error;


/// Information about a signature implementation
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct SignatureInfo {
	/// The name
	pub name: &'static str,
	
	/// The signature length
	pub signature_len: usize,
	
	/// The length of the private key part
	pub sec_key_length: usize,
	/// The length of the public key
	pub pub_key_length: usize
}


/// A stateless (oneshot) signature interface
pub trait Signer {
	/// Returns information about the MAC
	fn info(&self) -> SignatureInfo;
	
	/// Creates a new random private key and stores it in `buf` and returns the private key length
	fn create_sec_key(&self, buf: &mut[u8]) -> Result<usize, Box<dyn Error>>;
	/// Writes the public key for `sec_key` into `buf` and returns the public key length
	fn get_pub_key(&self, buf: &mut[u8], sec_key: &[u8]) -> Result<usize, Box<dyn Error>>;
	
	/// Signs `data` into `buf` using `key` and returns the signature length
	fn sign(&self, buf: &mut[u8], data: &[u8], sec_key: &[u8]) -> Result<usize, Box<dyn Error>>;
	/// Verifies `sig` for `data` with `pub_key` and returns `true` if the signature was valid
	fn verify(&self, data: &[u8], sig: &[u8], pub_key: &[u8]) -> Result<bool, Box<dyn Error>>;
}