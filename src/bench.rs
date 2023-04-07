//! Benchmarking

use cortex_m::peripheral::SYST;
use defmt::info;
use p256::{elliptic_curve::ScalarPrimitive, SecretKey, ecdsa::{SigningKey, Signature, signature::{Signer, Verifier}, VerifyingKey}};
use sha2::{Digest, Sha256};

use crate::time;

static CPU_FREQ: u64 = 72_000_000;

pub fn bench_sha2_rustcrypto(systick: &mut SYST) {
    info!("rustcrypto, sha2, small");

    let (hash, count) = time(systick, || {
        let mut summary = 0u8;
        for _ in 0 .. 128 {
            let mut hasher = Sha256::new();
            hasher.update(b"Hello world");
            let hash = hasher.finalize();
            (summary, _) = summary.overflowing_add(hash[0]);
        }
        summary
    });
    info!("128 iters, {} ticks {}, ({})", count, Human(count), hash);

    info!("rustcrypto, sha2, large");
    info!("bytes: {}", BLOCK.len());

    let (hash, count) = time(systick, || {
        let mut summary = 0u8;
        for _ in 0 .. 1 {
            let mut hasher = Sha256::new();
            for _ in 0 .. 1024 {
                hasher.update(BLOCK);
            }
            let hash = hasher.finalize();
            (summary, _) = summary.overflowing_add(hash[0]);
        }
        summary
    });
    info!("1 iter, {} ticks {}, ({})", count, Human(count), hash);
}

pub fn bench_pkey_sign(systick: &mut SYST) {
    info!("p256 operations");

    static SECRET_BYTES: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let (pk, count) = time(systick, || {
        let bytes = ScalarPrimitive::from_slice(&SECRET_BYTES).unwrap();
        SecretKey::new(bytes)
    });
    info!("Load key from bytes: {} ticks", Human(count));

    // Perform a digital signature itself.
    let (sig, count) = time(systick, || {
        let pk = pk.clone();
        let signer = SigningKey::from(pk);
        let sig: Signature = signer.sign(b"Message to sign");
        sig
    });
    info!("Sign: {} ticks", Human(count));

    // Perform a signature verification.
    let (good, count) = time(systick, || {
        let verifier = VerifyingKey::from(pk.public_key());
        verifier.verify(b"Message to sign", &sig).is_ok()
    });
    info!("Verify: {} ticks, true={}", Human(count), good);
}

// A block of data that we can use to hash larger amounts of data.
static BLOCK: &[u8] = b"This is a fairly long block of data \
                        that we can use to consider hashing larger \
                        amounts ot data.  We'll just put stuff here \
                        until we tune it to 256 bytes.  Which, admittedly \
                        could actually be a bit tedious.  The contents \
                        of this block doesn't really matter.";

// Wrap a time tick with something that will make it print in a nice
// human-readable format.
struct Human(u64);

impl defmt::Format for Human {
    fn format(&self, f: defmt::Formatter) {
        let mut time = self.0 as f32 / CPU_FREQ as f32;
        let mut pos = 0;
        while pos < UNITS.len() - 1 && time < 1.0 {
            pos += 1;
            time *= 1000.0;
        }
        defmt::write!(f, "{}{}", time, UNITS[pos])
    }
}

static UNITS: [&'static str; 5] = [
    "s", "ms", "us", "ns", "***"
];
