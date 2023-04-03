//! Prints "Hello, world!" on the host console using semihosting

#![no_main]
#![no_std]

use panic_halt as _;

use cortex_m::asm;
use cortex_m_rt::entry;
use cortex_m_semihosting::hprintln;

use cortex_m::peripheral::{syst, Peripherals};

use sha2::{Digest, Sha256};

#[entry]
fn main() -> ! {
    hprintln!("Hello, world!").unwrap();

    let peripherals = Peripherals::take().unwrap();
    let mut systick = peripherals.SYST;
    systick.set_clock_source(syst::SystClkSource::Core);
    systick.set_reload(12_000_000);
    systick.clear_current();
    systick.enable_counter();
    // while !systick.has_wrapped() {
    //     // loop
    // }
    asm::nop();
    // let a = systick.cvr.read();
    // // let wra = systick.has_wrapped();
    // let b = systick.cvr.read();
    // // let wrb = systick.has_wrapped();
    // hprintln!("a = {}", a).unwrap();
    // hprintln!("b = {}", b).unwrap();
    // let c = systick.cvr.read();
    // // let wrc = systick.has_wrapped();
    // hprintln!("c = {}", c).unwrap();
    // // hprintln!("c-b = {}", c - b).unwrap();
    // hprintln!("one read {}", a-b).unwrap();
    // hprintln!("one print {}", b-c).unwrap();

    let pre = systick.cvr.read();
    // let mut hasher = Sha256::new();
    // hasher.update(b"hello world");
    // let hash = hasher.finalize();
    let post = systick.cvr.read();
    let hash = b"foo";
    hprintln!("Hash bytes are {} ({} ticks)", hash[0], pre-post).unwrap();

    // exit QEMU
    // NOTE do not run this on hardware; it can corrupt OpenOCD state
    // debug::exit(debug::EXIT_SUCCESS);

    loop {}
}
