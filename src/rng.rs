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