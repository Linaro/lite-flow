#![no_std]
#![no_main]

extern crate alloc;

use core::{sync::atomic::{AtomicU32, Ordering}, fmt::Write};

use defmt::info;
use defmt_rtt as _;

use embedded_alloc::Heap;
use hal::{serial::Serial, gpio::{self, AF7, PushPull}};
// pick a panicking behavior
// use panic_halt as _; // you can put a breakpoint on `rust_begin_unwind` to catch panics
// use panic_abort as _; // requires nightly
// use panic_itm as _; // logs messages over ITM; requires ITM support
// use panic_semihosting as _; // logs messages to the host stderr; requires a debugger
use panic_probe as _;

use cortex_m::{
    asm,
    peripheral::{syst, SYST},
    Peripherals,
};
use cortex_m_rt::{entry, exception};

use stm32f3xx_hal::{self as hal, pac, prelude::*};

mod bench;
mod errors;
mod pdump;

type Result<T> = core::result::Result<T, errors::AppError>;

#[global_allocator]
static HEAP: Heap = Heap::empty();

static TICK_BASE: u32 = 12_000_000;

static WRAP_COUNT: AtomicU32 = AtomicU32::new(0);

#[entry]
fn main() -> ! {
    // Initialize a small heap to make some things easier.
    {
        use core::mem::MaybeUninit;
        const HEAP_SIZE: usize = 4096;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }
    }
    let dp = pac::Peripherals::take().unwrap();

    defmt::error!("Error level message: {}", 42);

    defmt::println!("Hello world: defmt println");

    let mut flash = dp.FLASH.constrain();
    let mut rcc = dp.RCC.constrain();

    let clocks = rcc.cfgr
        .use_hse(8.MHz())
        .hclk(72.MHz())
        .sysclk(72.MHz())
        .pclk1(12.MHz())
        .pclk2(12.MHz())
        .freeze(&mut flash.acr);

    type SerialType = Serial<pac::USART1, (gpio::PC4<AF7<PushPull>>, gpio::PC5<AF7<PushPull>>)>;
    let mut gpioc = dp.GPIOC.split(&mut rcc.ahb);
    let mut pins = (
        gpioc.pc4.into_af_push_pull(&mut gpioc.moder, &mut gpioc.otyper, &mut gpioc.afrl),
        gpioc.pc5.into_af_push_pull(&mut gpioc.moder, &mut gpioc.otyper, &mut gpioc.afrl),
    );
    pins.1.internal_pull_up(&mut gpioc.pupdr, true);
    let mut serial: SerialType =
        Serial::new(dp.USART1, pins, 115200.Bd(), clocks, &mut rcc.apb2);
    serial.write_str("Hello world via the UART\r\n").unwrap();
    // for b in b"Hello world\r\n" {
    //     while serial.is_busy() {
    //     }
    //     serial.write(*b).unwrap();
    // }
    // serial.write_all(b"Hello world\r\n").unwrap();

    let peripherals = Peripherals::take().unwrap();
    let mut systick = peripherals.SYST;

    systick.set_clock_source(syst::SystClkSource::Core);
    systick.set_reload(TICK_BASE - 1);
    systick.clear_current();
    systick.enable_counter();

    // Short timer.
    let timer = Timer::new(systick);
    asm::nop();
    let (wraps, count, mut systick) = timer.stop();
    info!("Empty tick: {},{}", wraps, count);

    bench::bench_sha2_rustcrypto(&mut systick);
    bench::bench_pkey_sign(&mut systick);
    bench::bench_encrypt0(&mut systick);
    bench::bench_sign1(&mut systick);

    // Let's try a panic.
    // #[allow(unconditional_panic)]
    // let _ = 1 / 0;
    cortex_m::asm::bkpt();

    // if true {
    //     panic!("Early stop");
    // }

    // let (hash, count) = time(&mut systick, || {
    //     let mut hasher = Sha256::new();
    //     hasher.update(b"hello world");
    //     hasher.finalize()
    // });
    // hprintln!("Hash bytes are ({}) ({} ticks)", hash[0], count).unwrap();

    // // Build a key out of a private piece of data.  We don't yet have a cprng, so just hardcode a fixed key.
    // static SECRET_BYTES: [u8; 32] = [
    //     1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    //     26, 27, 28, 29, 30, 31, 32,
    // ];
    // let (pk, count) = time(&mut systick, || {
    //     let bytes = ScalarPrimitive::from_slice(&SECRET_BYTES).unwrap();
    //     SecretKey::new(bytes)
    // });
    // hprintln!("Secret: {:?} {} ticks", pk, count).unwrap();

    // let (sig, count) = time(&mut systick, || {
    //     let pk = pk.clone();
    //     let signer = SigningKey::from(pk);
    //     let sig: Signature = signer.sign(b"Message to sign");
    //     sig
    // });
    // hprintln!("Signature: {} ticks {:?}", count, sig).unwrap();
    // hprintln!("Wrap count: {}", WRAP_COUNT.load(Ordering::SeqCst)).unwrap();

    // // Extract the public key.
    // let (pubkey, count) = time(&mut systick, || {
    //     let pubkey = pk.public_key();
    //     pubkey.as_affine().x()[0]
    // });
    // hprintln!("Pub {} ticks: {:?}", pubkey, count).unwrap();

    // static TEST_KEY: [u8; 16] = [
    //     1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    // ];
    // let plain = b"12345678";
    // let mut ciphertext: heapless::Vec<u8, 24> = heapless::Vec::new();
    // let mut cipher = Aes128Gcm::new_from_slice(&TEST_KEY).unwrap();
    // let ((), count) = time(&mut systick, || {
    //     let nonce = Nonce::from_slice(b"unique nonce");
    //     ciphertext.extend_from_slice(plain).unwrap();
    //     cipher.encrypt_in_place(&nonce, b"", &mut ciphertext).unwrap();
    //     ()
    // });
    // hprintln!("Cipher: {} ticks: {}", count, ciphertext[0]).unwrap();

    // asm::nop(); // To not have main optimize to abort in release mode, remove when you add code

    loop {
        // your code goes here
        panic!("Stop!");
    }
}

/// A basic timer, owns the systick peripheral for the duration.  Assumes basic setup.
struct Timer {
    systick: SYST,
}

impl Timer {
    fn new(mut systick: SYST) -> Timer {
        systick.disable_counter();
        systick.clear_current();
        WRAP_COUNT.store(0, Ordering::SeqCst);
        systick.enable_interrupt();
        systick.enable_counter();
        Timer { systick }
    }

    fn stop(mut self) -> (u32, u32, SYST) {
        self.systick.disable_counter();
        self.systick.disable_interrupt();
        // This is simpler because we can stop the counter.
        let count = TICK_BASE - self.systick.cvr.read();
        let wrap = WRAP_COUNT.load(Ordering::SeqCst);
        (wrap, count, self.systick)
    }
}

/// A functional timer, with callback.
pub fn time<F, R>(systick: &mut SYST, f: F) -> (R, u64)
where
    F: FnOnce() -> R,
{
    systick.disable_counter();
    systick.clear_current();
    WRAP_COUNT.store(0, Ordering::SeqCst);
    systick.enable_interrupt();
    systick.enable_counter();
    asm::nop();
    let result = f();
    systick.disable_counter();
    systick.disable_interrupt();
    let count = TICK_BASE - systick.cvr.read();
    let wrap = WRAP_COUNT.load(Ordering::SeqCst);
    (result, wrap as u64 * TICK_BASE as u64 + count as u64)
}

// Tick handler
#[exception]
fn SysTick() {
    let _ = WRAP_COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
}
