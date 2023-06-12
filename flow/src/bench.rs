//! Benchmarking

extern crate alloc;

use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit, Nonce};
use aes_kw::{KekAes128, Kek};
use alloc::string::ToString;
use alloc::{vec, string::String};
use alloc::vec::Vec;
use core::convert::TryFrom;
use coset::{Header, RegisteredLabelWithPrivate, ProtectedHeader, CoseKdfContextBuilder, SuppPubInfo, CoseRecipientBuilder, CoseEncryptBuilder};
use coset::{cbor::value::Value, iana, CborSerializable, CoseEncrypt0Builder, HeaderBuilder};
use defmt::info;
use p256::PublicKey;
use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{ScalarPrimitive, sec1::ToEncodedPoint},
    SecretKey,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{errors::AppError, pdump::HexDump, time, Result};

pub async fn bench_sha2_rustcrypto() {
    info!("rustcrypto, sha2, small");

    let hash = time("128 iters", async || {
        let mut summary = 0u8;
        for _ in 0..128 {
            let mut hasher = Sha256::new();
            hasher.update(b"Hello world");
            let hash = hasher.finalize();
            (summary, _) = summary.overflowing_add(hash[0]);
        }
        summary
    }).await;
    info!("hash: {}", hash);

    info!("rustcrypto, sha2, large");
    info!("bytes: {}", BLOCK.len());

    let hash = time("1 iter", async || {
        let mut summary = 0u8;
        for _ in 0..1 {
            let mut hasher = Sha256::new();
            for _ in 0..1024 {
                hasher.update(BLOCK);
            }
            let hash = hasher.finalize();
            (summary, _) = summary.overflowing_add(hash[0]);
        }
        summary
    }).await;
    info!("hash: {}", hash);
}

pub async fn bench_pkey_sign() {
    info!("p256 operations");

    static SECRET_BYTES: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let pk = time("load key", async || {
        let bytes = ScalarPrimitive::from_slice(&SECRET_BYTES).unwrap();
        SecretKey::new(bytes)
    }).await;

    // Perform a digital signature itself.
    let sig = time("sign", async || {
        let pk = pk.clone();
        let signer = SigningKey::from(pk);
        let sig: Signature = signer.sign(b"Message to sign");
        sig
    }).await;

    // Perform a signature verification.
    let good = time("verify", async || {
        let verifier = VerifyingKey::from(pk.public_key());
        verifier.verify(b"Message to sign", &sig).is_ok()
    }).await;
    info!("true={}", good);
}

// Wraps an AES key, and keps the private key around.
pub struct ContentKey {
    cipher: Aes128Gcm,
    #[allow(dead_code)]
    secret_bytes: Vec<u8>,
}

impl ContentKey {
    pub fn from_slice(data: &[u8]) -> Result<ContentKey> {
        Ok(ContentKey {
            secret_bytes: data.to_vec(),
            cipher: Aes128Gcm::new_from_slice(data).map_err(|_| AppError::AESError)?,
        })
    }

    pub fn encrypt(
        &self,
        plain: &[u8],
        session_id: &[u8],
        mut rng: impl CryptoRng + RngCore,
    ) -> Result<Vec<u8>> {
        let mut iv = vec![0u8; 12];
        rng.fill_bytes(&mut iv);
        let nonce = Nonce::from_slice(&iv);
        let packet = CoseEncrypt0Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(iana::Algorithm::A128GCM)
                    .value(-65537, Value::Bytes(session_id.to_vec()))
                    .build(),
            )
            .unprotected(HeaderBuilder::new().iv(iv.clone()).build())
            .create_ciphertext(plain, &[], |plaintext, aad| {
                let mut result = plaintext.to_vec();
                self.cipher
                    .encrypt_in_place(nonce, aad, &mut result)
                    .unwrap();
                result
            })
            .build();
        Ok(packet.to_vec().map_err(|_| AppError::AESError)?)
    }
}

pub async fn bench_encrypt0() {
    static SECRET_BYTES: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let secret = time("load aes key", async || ContentKey::from_slice(&SECRET_BYTES).unwrap()).await;

    let packet = time("encrypt0", async || secret.encrypt(b"plain", b"session", FakeRng)).await;
    let packet = packet.unwrap();
    packet.dump();
}

pub struct Key {
    info: KeyInfo,
    key_id: String,
}

pub enum KeyInfo {
    Secret(SecretKey),
    // Public(PublicKey),
}

impl Key {
    #[allow(dead_code)]
    pub fn from_slice(data: &[u8]) -> Result<Key> {
        let bytes = ScalarPrimitive::from_slice(data).map_err(|_| AppError::ECError)?;
        let pk = SecretKey::new(bytes);

        Ok(Key {
            info: KeyInfo::Secret(pk),
            key_id: "fake-key-id".to_string(),
        })
    }

    pub fn new(rng: &mut (impl CryptoRng + RngCore), key_id: &str) -> Result<Key> {
        Ok(Key {
            info: KeyInfo::Secret(SecretKey::random(rng)),
            key_id: key_id.to_string(),
        })
    }

    /// Retrieve the public key associated with this Key.
    pub fn public_key(&self) -> PublicKey {
        match &self.info {
            KeyInfo::Secret(sec) => sec.public_key(),
            // KeyInfo::Public(public) => public.clone(),
        }
    }

    pub fn encrypt_cose(
        &self,
        plaintext: &[u8],
        recipient: &Self,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<Vec<u8>> {
        let mut cek = vec![0u8; 16];
        rng.fill_bytes(&mut cek);

        // The kek is the key encryption key, which is also just generated.
        let mut kek = vec![0u8; 16];
        rng.fill_bytes(&mut kek);

        // Generate an IV.
        let mut kw_iv = vec![0u8; 12];
        rng.fill_bytes(&mut kw_iv);

        // There is an ephermeral key as well that we use to derive the shared
        // key we wrap with.
        let eph_key = SecretKey::random(&mut rng);

        // Extract the x and y values from this, as be_bytes.
        let eph_pub = eph_key.public_key();
        let encoded = eph_pub.as_affine().to_encoded_point(false);
        let encoded = encoded.as_bytes();
        assert_eq!(encoded.len(), 65);
        assert_eq!(encoded[0], 4);
        let eph_x = &encoded[1..33];
        let eph_y = &encoded[33..65];

        // Build a protected header for the recipient as this is needed for the
        // key derivation context.
        let prot_hd = Header {
            alg: Some(RegisteredLabelWithPrivate::Assigned(
                iana::Algorithm::ECDH_ES_A128KW,
            )),
            ..Default::default()
        };
        let item_map = Value::Map(vec![
            (Value::Integer(From::from(1)), Value::Integer(From::from(2))),
            (Value::Integer(From::from(-1)), Value::Integer(From::from(1))),
            (Value::Integer(From::from(-2)), Value::Bytes(eph_x.to_vec())),
            (Value::Integer(From::from(-3)), Value::Bytes(eph_y.to_vec())),
        ]);
        let unprot_hd = HeaderBuilder::new()
            .key_id(recipient.key_id.clone().into_bytes())
            .value(-1, item_map)
            .build();

        // There is a bit of a catch-22 in building this. The API seems to
        // suggest using the recipient to build the protected header from the
        // header, but we need it to build the context before we can encrypt the
        // data. As such, we build a temporary one, even though there isn't a
        // builder for this.
        let prot_full_hd = ProtectedHeader {
            original_data: None,
            header: prot_hd.clone(),
        };

        // Use this to build the aead handler for this.
        let cipher = Aes128Gcm::new_from_slice(&cek).map_err(|_| AppError::ECError)?;
        let nonce = Nonce::from_slice(&kw_iv);

        // Use HKDF to derive the secret from this. From our perspective, this
        // is based on the secret from the ephemeral key, and the public data of
        // the recipient.
        let alg = iana::Algorithm::A128KW;
        let ctxb = CoseKdfContextBuilder::new()
            .supp_pub_info(SuppPubInfo {
                key_data_length: 128,
                protected: prot_full_hd,
                other: None,
            })
            .algorithm(alg)
            .build();
        let ctx = ctxb.to_vec().map_err(|_| AppError::ECError)?;

        let secret = p256::ecdh::diffie_hellman(
            eph_key.to_nonzero_scalar(),
            recipient.public_key().as_affine(),
        );
        let hkdf = secret.extract::<sha2::Sha256>(None);
        let mut hkey = vec![0u8; 16];
        hkdf.expand(&ctx, &mut hkey).unwrap();

        // Use AES-KW to wrap the cek.
        let wr: KekAes128 = Kek::try_from(hkey.as_slice()).unwrap();
        let mut ceke = vec![0u8; 24];
        wr.wrap(&cek, &mut ceke).unwrap();

        // Build the recipient.
        let recip = CoseRecipientBuilder::new()
            .protected(prot_hd)
            .unprotected(unprot_hd)
            .ciphertext(ceke)
            .build();

        // Build the cose header (the above was the recipient header).
        let cose_prot_hd = HeaderBuilder::new()
            .algorithm(iana::Algorithm::A128GCM)
            .build();
        let cose_unprot_hd = HeaderBuilder::new().iv(kw_iv.to_vec()).build();

        // Build all of it.
        let packet = CoseEncryptBuilder::new()
            .add_recipient(recip)
            .protected(cose_prot_hd)
            .unprotected(cose_unprot_hd)
            .create_ciphertext(plaintext, &[], move |plain, aad| {
                let mut result = plain.to_vec();
                cipher.encrypt_in_place(nonce, aad, &mut result).unwrap();
                result
            })
            .build();

        // println!("Packet: {:#?}", packet);

        Ok(packet.to_vec().map_err(|_| AppError::ECError)?)
    }
}

pub async fn bench_sign1() {
    let secret = time("load EC key", async || {
        Key::new(&mut FakeRng, "key-id").unwrap()
        // Key::from_slice(&SECRET_BYTES).unwrap();
    }).await;
    let recipient = Key::new(&mut FakeRng, "recip-id").unwrap();
    let packet = time("core sign1(cose encrypt)", async || {
        secret.encrypt_cose(
            b"plain",
            &recipient,
            FakeRng,
        )
    }).await;
    let packet = packet.unwrap();
    packet.dump();
}

struct FakeRng;

impl RngCore for FakeRng {
    fn next_u32(&mut self) -> u32 {
        1
    }
    fn next_u64(&mut self) -> u64 {
        1
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for i in 1..dest.len() {
            dest[i] = 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FakeRng {}

// A block of data that we can use to hash larger amounts of data.
static BLOCK: &[u8] = b"This is a fairly long block of data \
                        that we can use to consider hashing larger \
                        amounts ot data.  We'll just put stuff here \
                        until we tune it to 256 bytes.  Which, admittedly \
                        could actually be a bit tedious.  The contents \
                        of this block doesn't really matter.";

/*
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

static UNITS: [&'static str; 5] = ["s", "ms", "us", "ns", "***"];

*/
