//! Various utility functions

use anyhow::Result;
use thiserror::Error;

use std::collections::hash_map::DefaultHasher;
use std::collections::{VecDeque, HashSet};
use std::hash::Hash;
use std::hash::Hasher;
use std::path::Path;
use std::str::FromStr;

use crate::fuzz_input::FuzzInput;
use crate::{Symbol, VirtAddr};

/// Print a hexdump representation of given data bytes
///
/// Example:
///
/// ```
/// hexdump([0x41, 0x42, 0x43, 0x44], 0xdead0000)
/// 0xdead0000: 41 42 43 44 | ABCD
/// ```
///
use crate::colors::Colorized;

/// Prints a hexdump representation of the given `data` assuming the data starts at
/// `starting_address`
pub fn hexdump(data: &[u8], starting_address: u64) {
    println!(
        "{:-^18}   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF",
        " address "
    );

    let mut prev_chunk: &[u8] = &[2_u8; 0x10];
    let mut prev_chunk_id = 0;

    for (i, chunk) in data.chunks(0x10).enumerate() {
        if chunk == prev_chunk {
            if i - prev_chunk_id == 1 {
                println!(
                    "{:#018x}: {}",
                    starting_address + i as u64 * 0x10,
                    "** repeated line(s) **".red()
                );
            }
            continue;
        }

        // Store the current chunk as the most recent unique line
        prev_chunk = chunk;
        prev_chunk_id = i;

        // Display the current address
        print!("{:#018x}: ", starting_address + i as u64 * 0x10);

        // Display the bytes
        for b in chunk {
            match b {
                0x00 => print!("{:02x} ", b.green()),
                0x0a | 0xff => print!("{:02x} ", b.red()),
                0x21..0x7e => print!("{:02x} ", b.yellow()),
                0x7f => print!("{:02x} ", b.blue()),
                _ => print!("{:02x} ", b.white()),
            }
        }

        // Pad chunks that are not 16 bytes wide
        if chunk.len() < 16 {
            print!("{}", " ".repeat((16 - chunk.len()) * 3));
        }

        // Add the separation
        print!(" | ");

        // Display the bytes as characters
        for b in chunk {
            match b {
                0x00 => print!("{}", '.'.green()),
                0x0a | 0xff => print!("{}", '.'.red()),
                0x21..0x7e => print!("{}", (*b as char).yellow()),
                0x7f => print!("{}", '.'.blue()),
                _ => print!("{}", '.'.white()),
            }
        }

        // Go to the next line
        println!();
    }
}

/// Wrapper around `rdtsc`
#[must_use]
pub fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Returns the hash of the given input using [`DefaultHasher`]
pub fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

/// Returns the formatted hash of the given input as hexadecimal digits
pub fn hexdigest<T: Hash>(t: &T) -> String {
    let h = calculate_hash(t);
    format!("{h:016x}")
}

/// Do the same as save_input_in_dir but with a hash
pub fn save_input_in_dir_with_cov(input: &impl FuzzInput, dir: &Path,inp_hash: &u64,cov_report:&String) -> Result<usize> {
    let mut input_bytes: Vec<u8> = vec![];
    input.to_bytes(&mut input_bytes)?;
    let length = input_bytes.len();

    // Create the filename for this input
    //let filename = hexdigest(&input);
    // We are going to use the hash as the file name of the input
    // Write the input
    let filename = inp_hash.to_string();
    // make a folder called corpus and update it to that
    let tmp_path_corp = dir.join("benign-corpus");
    if !tmp_path_corp.exists(){
        std::fs::create_dir_all(tmp_path_corp);
    }
    let filepath = dir.join("benign-corpus").join(filename.clone());
    if !filepath.exists() {
        std::fs::write(filepath, input_bytes)?;
    }
    // make a folder called coverage if it does not exist
    let tmp_path_cov = dir.join("benign-coverage");
    if !tmp_path_cov.exists(){
        std::fs::create_dir_all(tmp_path_cov);
    }
    std::fs::create_dir_all(dir.join("benign-coverage"))?;
    let cov_hash_file = dir.join("benign-coverage").join(filename.clone());
    if !cov_hash_file.exists() {
        std::fs::write(cov_hash_file,cov_report)?;
    }
    Ok(length)
}

/// Save the [`FuzzInput`] into the directory using the hash of input as the filename
///
/// # Errors
///
/// * Given `input.to_bytes()` failed
/// * Failed to write the bytes to disk
pub fn save_input_in_dir(input: &impl FuzzInput, dir: &Path) -> Result<usize> {
    let mut input_bytes: Vec<u8> = vec![];
    input.to_bytes(&mut input_bytes)?;
    let length = input_bytes.len();

    // Create the filename for this input
    let filename = hexdigest(&input);

    // Write the input
    let filepath = dir.join(filename);
    if !filepath.exists() {
        std::fs::write(filepath, input_bytes)?;
    }

    Ok(length)
}

/// Write the input and kcov to the directory    
pub fn save_input_in_dir_cov(input: &impl FuzzInput, dir: &Path, kcov: &HashSet<u64>,symbols:&Option<VecDeque<Symbol>>,kcov_path: &Path) -> Result<usize> {
    let mut input_bytes: Vec<u8> = vec![];
    input.to_bytes(&mut input_bytes)?;
    let length = input_bytes.len();

    // Create the filename for this input
    let filename = hexdigest(&input);

    // Write the input
    let filepath = dir.join(filename.clone());
    if !filepath.exists() {
        std::fs::write(filepath, input_bytes)?;
    }
    
    // Write the kcov to the file with name hexdigest + kcov
    let kcov_filename = format!("{}", hexdigest(&input));
    let kcov_filepath = kcov_path.join(kcov_filename);
    if !kcov_filepath.exists() {
        let all_symbols_str = get_kcov_string(kcov,symbols); 
        std::fs::write(kcov_filepath, all_symbols_str)?;
    }

    Ok(length)
}

/// Write the user+kernel coverage to a file
pub fn write_coverage_in_dir(input: &impl FuzzInput, dir: &Path, coverage: &Vec<u64>) -> Result<usize> {
    // Create the filename for this input
    let filename = hexdigest(&input);

    // Write the coverage
    let filepath = dir.join(filename);
    if !filepath.exists() {
        std::fs::write(
            filepath,
            coverage
                .iter()
                .map(|addr| format!("{:#x}", addr))
                .collect::<Vec<_>>()
                .join("\n"),
        )?;
    }

    Ok(coverage.len())
}

/// Write the input and kcov to the directory
pub fn get_kcov_string(kcov: &HashSet<u64>,symbols:&Option<VecDeque<Symbol>>) -> String {
    let mut symbol_strings = Vec::new();
    for addr in kcov {
        if let Some(ref sym_data) = symbols {
            let mut curr_symbol = crate::symbols::get_symbol(*addr, sym_data)
                    .unwrap_or_else(|| "UnknownSym".to_string());
        // remove the + from the curr_symbol
        let curr_symbol = curr_symbol.split("+").collect::<Vec<&str>>()[0].to_string();
        symbol_strings.push(curr_symbol);
        } 
    }
    // Remove duplicates
    symbol_strings.sort();
    symbol_strings.dedup();
    return symbol_strings.join("\n");
}

/// Errors that can be triggered during `project` subcommand
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid symbol format: `symbol`, `symbol!offset`, `symbol+offset`
    #[error("Invalid symbol format: `symbol`, `symbol!offset`, `symbol+offset`")]
    InvalidSymbolFormat(String),

    /// Symbol offset failed to parse to a `u64`
    #[error("Symbol offset failed to parse to a `u64`")]
    InvalidSymbolOffset(String),

    /// Did not find symbol
    #[error("Invalid symbol format: `symbol`, `symbol!offset`, `symbol+offset`")]
    SymbolNotFound,
}

/// Parse the given `argument` as a `VirtAddr`
///
/// Examples:
///
/// ```
/// deadbeef
/// 0xdeadbeef
/// main
/// main+123
/// main+0x123
/// ```
///
/// # Errors
///
/// * Attempted to parse an unknown symbol format
/// * Requested symbol is not found
pub fn parse_cli_symbol(
    possible_virt_addr: &str,
    symbols: &Option<VecDeque<Symbol>>,
) -> Result<VirtAddr> {
    // Parse the given translation address or default to the starting RIP of the snapshot
    let parsed = VirtAddr::from_str(possible_virt_addr);

    if let Ok(addr) = parsed {
        Ok(addr)
    } else {
        let Some(symbols) = symbols.as_ref() else {
            return Err(Error::SymbolNotFound.into());
        };

        // Failed to parse the argument as a `VirtAddr`. Try to parse it as a
        // symbol of the following forms
        // `symbol`
        // `symbol+offset`
        let mut offset = 0;
        let virt_addr = possible_virt_addr;
        let mut symbol = virt_addr.to_string();
        let mut addr = None;

        if virt_addr.contains('+') {
            let mut iter = virt_addr.split('+');
            symbol = iter
                .next()
                .ok_or_else(|| Error::InvalidSymbolFormat(virt_addr.to_string()))?
                .to_string();

            let curr_offset = iter
                .next()
                .ok_or(Error::InvalidSymbolFormat(virt_addr.to_string()))?;

            let no_prefix = curr_offset.trim_start_matches("0x");

            // Attempt to parse the hex digit
            offset = u64::from_str_radix(no_prefix, 16)
                .map_err(|_| Error::InvalidSymbolOffset(offset.to_string()))?;
        }

        log::info!("Checking for symbol: {symbol}+{offset:#x}");

        let mut subsymbols = Vec::new();

        // Add the fuzzer specific symbols
        for Symbol {
            address,
            symbol: curr_symbol,
        } in symbols
        {
            if *curr_symbol == symbol {
                addr = Some(VirtAddr(*address).offset(offset));
            } else if curr_symbol.contains(&symbol) {
                subsymbols.push((curr_symbol, VirtAddr(*address).offset(offset)));
            }
        }

        if let Some(found) = addr {
            Ok(found)
        } else {
            if subsymbols.len() == 1 {
                log::info!("Did not find symbol {symbol}, but found 1 subsymbol.. using this one");
                return Ok(subsymbols[0].1);
            }

            log::error!("Did not find symbol {symbol}");
            if !subsymbols.is_empty() {
                log::error!("Did find symbols containing {symbol}. One of these might be a more specific symbol:");

                let min = subsymbols.len().min(50);
                if subsymbols.len() > 50 {
                    log::info!(
                        "Here are the first {min}/{} symbols containing {symbol}",
                        subsymbols.len()
                    );
                }

                for (subsymbol, _) in subsymbols.iter().take(min) {
                    log::info!("- {subsymbol}");
                }
            }

            Err(Error::SymbolNotFound.into())
        }
    }
}
