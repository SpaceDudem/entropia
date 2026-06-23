// SPDX-License-Identifier: Apache-2.0
// run_bin.rs — load an EntropyKit .bin and execute it. Linux x86-64 only.
// Build: rustc -O run_bin.rs -o run_bin
// Use:   ./run_bin example/gc_demo.bin
//
// On Windows the equivalent is the bundled `example/sclauncher64.exe`,
// which does VirtualAlloc(PAGE_EXECUTE_READWRITE) + memcpy + call.

use std::env;
use std::ffi::c_void;
use std::fs;

extern "C" {
    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
}
const PROT_READ:    i32 = 1;
const PROT_WRITE:   i32 = 2;
const PROT_EXEC:    i32 = 4;
const MAP_PRIVATE:  i32 = 0x02;
const MAP_ANON:     i32 = 0x20;

fn main() {
    let path = env::args().nth(1).expect("usage: run_bin <file.bin>");
    let bytes = fs::read(&path).expect("read");
    let len = (bytes.len() + 4095) & !4095;

    unsafe {
        let p = mmap(std::ptr::null_mut(), len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
        assert!(p as isize != -1, "mmap failed");
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p as *mut u8, bytes.len());

        // EntropyKit emits Win64 calling convention (args in rcx/rdx/r8/r9).
        // On Linux rcx isn't a "host services" pointer; main's prologue still
        // saves it, but `shared.*` will see NULL and short-circuit to zero.
        // For zero-arg main(), rcx is irrelevant — rax holds the return value.
        let entry: extern "win64" fn() -> i64 = std::mem::transmute(p);
        let result = entry();
        println!("returned: {} (0x{:x})", result, result);

        munmap(p, len);
    }
}
