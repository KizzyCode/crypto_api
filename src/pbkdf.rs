use std::error::Error;


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
	
	/// The minimum supported salt length
	pub salt_len_min: usize,
	/// The maximum supported salt length
	pub salt_len_max: usize,
	
	/// The KDFs default CPU cost
	pub cpu_cost: u64,
	/// The minimum supported CPU cost
	pub cpu_cost_min: u64,
	/// The maximum supported CPU cost
	pub cpu_cost_max: u64,
	
	/// Specific information for memory hard PBKDFs
	pub memory_hard_pbkdf_info: Option<MemoryHardPbkdfInfo>
}

/// Information about a memory-hard PBKDF implementation
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct MemoryHardPbkdfInfo {
	/// The KDFs default memory cost
	pub memory_cost: u64,
	/// The minimum supported memory cost
	pub memory_cost_min: u64,
	/// The maximum supported memory cost
	pub memory_cost_max: u64,
	
	/// The KDFs default parallelism
	pub parallelism: u64,
	/// The minimum supported parallelism
	pub parallelism_min: u64,
	/// The maximum supported parallelism
	pub parallelism_max: u64
}


/// A stateless (oneshot) PBKDF interface
pub trait Pbkdf {
	/// Returns information about the PBKDF
	fn info(&self) -> PbkdfInfo;
	
	/// Fills `buf` with key bytes derived from `password` parametrized by `cpu_cost`
	fn derive(&self, buf: &mut[u8], password: &[u8], salt: &[u8], cpu_cost: u64)
		-> Result<(), Box<dyn Error + 'static>>;
}

/// A stateless (oneshot) memory-hard PBKDF interface
pub trait MemoryHardPbkdf: Pbkdf {
	/// Fills `buf` with key bytes derived from `password` parametrized by `cpu_cost`
	fn derive_memory_hard(&self, buf: &mut[u8], password: &[u8], salt: &[u8], cpu_cost: u64,
		memory_cost: u64, parallelism: u64) -> Result<(), Box<dyn Error + 'static>>;
}