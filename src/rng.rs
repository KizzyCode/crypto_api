use std::error::Error;


/// A random number generator
pub trait Rng {
	/// Returns if `Rng` is cryptographically secure
	fn is_secure(&self) -> bool;
	
	/// Fills `buf` with random data
	fn random(&mut self, buf: &mut[u8]) -> Result<(), Box<dyn Error + 'static>>;
}

/// A seedable random number generator
pub trait SeedableRng: Rng {
	/// Seeds `seed` into the `SeedableRng`
	fn seed(&mut self, seed: &[u8]) -> Result<(), Box<dyn Error + 'static>>;
}

/// A deterministic random number generator
pub trait DeterministicRng: Rng {
	/// Reseeds the `DeterministicRng` with `seed`
	fn reseed(&mut self, seed: &[u8]) -> Result<(), Box<dyn Error + 'static>>;
}


/// A algorithm specific key generator to generate a (secret) key
pub trait SecKeyGen {
	/// Generates a new key into `buf` and returns the length of the secret key
	fn new_secret_key(&self, buf: &mut[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}

/// A algorithm specific trait to compute a public key from a secret key
pub trait PubKeyGen {
	/// Computes the public key from `secret_key` into `buf` and returns the length of the public
	/// key
	fn get_public_key(&self, buf: &mut[u8], secret_key: &[u8])
		-> Result<(), Box<dyn Error + 'static>>;
}