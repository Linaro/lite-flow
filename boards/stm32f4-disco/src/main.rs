#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

extern crate alloc;

use defmt::info;
use embassy_executor::Spawner;
use embassy_stm32::time::Hertz;
use embassy_stm32::Config;
use embassy_time::{Duration, Instant, Timer, TICK_HZ};
use embedded_alloc::Heap;
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
    config.rcc.sys_ck = Some(Hertz(168_000_000));
    let _p = embassy_stm32::init(config);

    flow::sample().await;

    info!("HZ: {}", TICK_HZ);
    info!("now: {}", Instant::now().as_micros());

    info!("Hello World!");
    Timer::after(Duration::from_secs(1)).await;
    info!("now: {}", Instant::now().as_micros());

    loop {}
}

// For now, just have this here that we can evaluate, and restart lsp.
// (lsp-workspace-folders-add "~/linaro/zep/lite-flow/boards/stm32f4-disco")
