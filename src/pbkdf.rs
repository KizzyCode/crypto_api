use ::std::error::Error;


/// Information about a PBKDF implementation
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct PbkdfInfo {
	/// The name
	pub name: &'static str,
	
	/// The minimum output length
	pub output_len_min: usize,
	/// The maximum output length
	pub output_len_max: usize,
	
	/// The minimum supported key length
	pub password_len_min: usize,
	/// The maximum supported key length
	pub password_len_max: usize,
	
	/// The KDFs default CPU cost
	pub cpu_cost: usize,
	/// The minimum supported CPU cost
	pub cpu_cost_min: usize,
	/// The maximum supported CPU cost
	pub cpu_cost_max: usize,
	
	/// Specific information for memory hard PBKDFs
	pub memory_hard_pbkdf_info: Option<MemoryHardPbkdfInfo>
}

/// Information about a memory-hard PBKDF implementation
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct MemoryHardPbkdfInfo {
	/// The KDFs default memory cost
	pub memory_cost: usize,
	/// The minimum supported memory cost
	pub memory_cost_min: usize,
	/// The maximum supported memory cost
	pub memory_cost_max: usize,
	
	/// The KDFs default parallelism
	pub parallelism: usize,
	/// The minimum supported parallelism
	pub parallelism_min: usize,
	/// The maximum supported parallelism
	pub parallelism_max: usize
}


/// A stateless (oneshot) PBKDF interface
pub trait Pbkdf {
	/// Returns information about the PBKDF
	fn info(&self) -> PbkdfInfo;
	
	/// Fills `buf` with key bytes derived from `password` parametrized by `cpu_cost`
	fn derive(&self, buf: impl AsMut<[u8]>, password: impl AsRef<[u8]>, cpu_cost: u64)
		-> Result<(), Box<Error>>;
}

/// A stateless (oneshot) memory-hard PBKDF interface
pub trait MemoryHardPbkdf: Pbkdf {
	/// Fills `buf` with key bytes derived from `password` parametrized by `cpu_cost`
	fn derive_memory_hard(&self, buf: impl AsMut<[u8]>, password: impl AsRef<[u8]>, cpu_cost: u64,
		memory_cost: u64, parallelism: u64) -> Result<(), Box<Error>>;
}