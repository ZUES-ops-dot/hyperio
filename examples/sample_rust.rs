//! Sample Rust code with intentional security issues for testing HyperionScan
//!
//! WARNING: This code is for TESTING ONLY. Do not use in production!

use std::process::Command;
use std::path::Path;

// VULNERABILITY: Static mutable variable
static mut GLOBAL_COUNTER: u32 = 0;

// VULNERABILITY: Hardcoded secret (dummy placeholder for testing)
const API_KEY: &str = "sk_test_REPLACE_ME";
const PRIVATE_KEY: &str = "0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";

/// Function with multiple security issues
pub fn vulnerable_function() {
    // VULNERABILITY: Unsafe block
    unsafe {
        GLOBAL_COUNTER += 1;
        println!("Counter: {}", GLOBAL_COUNTER);
    }
    
    // VULNERABILITY: Unwrap without error handling
    let result: Result<i32, &str> = Ok(42);
    let value = result.unwrap();
    
    // VULNERABILITY: Array indexing without bounds check
    let arr = [1, 2, 3];
    let idx = 2;
    let _element = arr[idx]; // Could panic on out-of-bounds
    
    // VULNERABILITY: Command execution
    let user_input = "ls";
    Command::new("sh")
        .arg("-c")
        .arg(user_input)
        .output()
        .expect("failed");
}

/// Unsafe function declaration
/// 
/// # Safety
/// Caller must ensure pointer is valid
pub unsafe fn dangerous_pointer_op(ptr: *mut u8) {
    // VULNERABILITY: Raw pointer dereference
    *ptr = 42;
}

/// Function using transmute
pub fn risky_transmute() {
    // VULNERABILITY: Transmute is extremely unsafe
    let bytes: [u8; 4] = [0, 0, 0, 1];
    let _num: u32 = unsafe { std::mem::transmute(bytes) };
}

/// Function with FFI
extern "C" {
    fn external_function(x: i32) -> i32;
}

pub fn call_ffi() {
    // VULNERABILITY: FFI boundary
    unsafe {
        let _result = external_function(42);
    }
}

/// Function with uninitialized memory
pub fn uninitialized_memory() {
    use std::mem::MaybeUninit;
    
    // VULNERABILITY: Uninitialized memory
    let uninit: MaybeUninit<[u8; 1024]> = MaybeUninit::uninit();
    
    // BAD: Assuming init when it's not
    // let data = unsafe { uninit.assume_init() };
}

/// Path manipulation
pub fn process_file(user_path: &str) {
    // VULNERABILITY: Path traversal possible
    let path = Path::new(user_path);
    
    // Should validate and canonicalize path
    if path.exists() {
        println!("Processing: {:?}", path);
    }
}

/// Overflow-prone arithmetic
pub fn arithmetic_ops(a: u32, b: u32) -> u32 {
    // VULNERABILITY: Wrapping arithmetic
    a.wrapping_add(b)
}

/// Better: Safe version with proper error handling
pub fn safe_function() -> Result<(), Box<dyn std::error::Error>> {
    // Good: Using ? operator for error propagation
    let result: Result<i32, &str> = Ok(42);
    let _value = result?;
    
    // Good: Using get() for bounds-checked access
    let arr = [1, 2, 3];
    if let Some(&element) = arr.get(1) {
        println!("Element: {}", element);
    }
    
    Ok(())
}

// TODO: Add more test cases
// FIXME: This module needs security review

fn main() {
    println!("This is a test file for HyperionScan");
    vulnerable_function();
}
