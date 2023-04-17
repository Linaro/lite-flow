#![no_std]
// Enable async closures.
#![feature(async_closure)]

extern crate alloc;

use core::future::Future;

use defmt::info;
use embassy_time::{Duration, Instant, Timer};

mod bench;
mod pdump;

pub type Result<T> = core::result::Result<T, errors::AppError>;

pub async fn sample() {
    info!("Sample is working");
    info!("See ticks: {}", Instant::now().as_micros());
    time("Baseline", async || {
        Timer::after(Duration::from_micros(100)).await;
    })
    .await;
    bench::bench_sha2_rustcrypto().await;
    bench::bench_pkey_sign().await;
    bench::bench_encrypt0().await;
    bench::bench_sign1().await;
}

/// A functional timer, perform the given operation, with a name, and print out
/// how long it too.
pub async fn time<F, O, R>(name: &str, f: F) -> O
where
    F: FnOnce() -> R,
    R: Future<Output = O>,
{
    let before = Instant::now();
    let result = f().await;
    let after = Instant::now();
    let length = (after - before).as_micros();
    if length < 1000 {
        info!("time {}: {}us", name, length);
    } else {
        info!("time {}: {}ms", name, length as f32 / 1000.0);
    }
    result
}

pub mod errors {
    #[derive(Debug)]
    pub enum AppError {
        AESError,
        ECError,
    }
}
