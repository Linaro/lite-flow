#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

extern crate alloc;

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::rcc::{ClockSrc, PllClkDiv, PllM, PllN, PllSrc};
use embassy_stm32::time::Hertz;
use embassy_stm32::Config;
use embedded_alloc::Heap;
// use embassy_stm32::gpio::{Level, Output, Speed};
// use embassy_time::{Duration, Timer};
use {defmt_rtt as _, panic_probe as _};

#[global_allocator]
static HEAP: Heap = Heap::empty();

#[embassy_executor::main]
async fn main(_spawner: Spawner) -> ! {
    // Initialize a small heap for the crypto routines.
    {
        use core::mem::MaybeUninit;
        const HEAP_SIZE: usize = 4096;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe {
            HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE);
        }
    }

    let mut config = Config::default();
    // config.rcc.mux = ClockSrc::PLL1R(
    //     PllSrc::HSE(Hertz(48_000_000)),
    //     PllM::Div2,
    //     PllN::Mul5,
    //     PllClkDiv::NotDivided,
    // );
    //config.rcc.mux = ClockSrc::MSI(MSIRange::Range48mhz);
    // config.rcc.hsi48 = true;
    let _p = embassy_stm32::init(config);
    info!("Hello World!");

    flow::sample().await;

    /*
    let mut led = Output::new(p.PH7, Level::Low, Speed::Medium);

    loop {
        defmt::info!("on!");
        led.set_low();
        Timer::after(Duration::from_millis(200)).await;

        defmt::info!("off!");
        led.set_high();
        Timer::after(Duration::from_millis(200)).await;
    }
    */
    loop {}
}

// (lsp-workspace-folders-add "~/linaro/zep/lite-flow/boards/stm32u585")
