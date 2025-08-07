#[cfg(feature = "pcs_table")]
pub mod pcs_table;

#[cfg(feature = "pc_guards")]
pub mod pc_guards;

#[cfg(feature = "trace_pc")]
pub mod trace_pc;

#[cfg(feature = "trace_pc_indirect")]
pub mod trace_pc_indirect;

#[cfg(feature = "inline_8bit_counters")]
pub mod inline_8bit_counters;

#[cfg(feature = "inline_bool_flags")]
pub mod inline_bool_flags;
