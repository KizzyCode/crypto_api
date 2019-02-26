use crate::rng::{ SecKeyGen, PubKeyGen };
use std::error::Error;


/// Information about a signature implementation
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct SignerInfo {
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
pub trait Signer: SecKeyGen + PubKeyGen {
	/// Returns information about the signer
	fn info(&self) -> SignerInfo;
	
	/// Signs `data` into `buf` using `secret_key` and returns the signature length
	fn sign(&self, buf: &mut[u8], data: &[u8], secret_key: &[u8])
		-> Result<usize, Box<dyn Error + 'static>>;
	/// Verifies `sig` for `data` with `public_key` and returns `true` if the signature was valid
	fn verify(&self, data: &[u8], sig: &[u8], public_key: &[u8])
		-> Result<bool, Box<dyn Error + 'static>>;
}