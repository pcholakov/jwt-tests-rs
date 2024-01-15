use std::fmt;
use std::fmt::{Debug, Display};
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use criterion::{BenchmarkId, black_box, Criterion, criterion_group, criterion_main, Throughput};
use jsonwebtoken::{Algorithm, decode, DecodingKey, encode, EncodingKey, Header, Validation};
use rand::Rng;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use ulid::Ulid;

use jwt_tests::Claims;

struct CreateTokenConfig {
    sub: String,
    tenant: String,
    algorithm: Algorithm,
    encode_key: EncodingKey,
}


fn bench_create_token_asymmetric(c: &mut Criterion) {
    let (private_key, _) = generate_rsa_key_pair().unwrap();
    let rsa_private_key = EncodingKey::from_rsa_der(private_key.to_pkcs1_der().unwrap().as_bytes());

    let expiry_time = SystemTime::now().add(Duration::from_secs(3600)).duration_since(UNIX_EPOCH).unwrap().as_secs();

    let rs256 = CreateTokenConfig {
        algorithm: Algorithm::RS256,
        encode_key: rsa_private_key,
        sub: Ulid::new().to_string(),
        tenant: Ulid::new().to_string(),
    };

    let ed_key_pair = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let ed_dsa = CreateTokenConfig {
        algorithm: Algorithm::EdDSA,
        encode_key: EncodingKey::from_ed_der(ed_key_pair.as_ref()),
        sub: Ulid::new().to_string(),
        tenant: Ulid::new().to_string(),
    };

    let mut key = [0u8; 128];
    rand::thread_rng().fill(&mut key[..]);

    let hs256 = CreateTokenConfig {
        algorithm: Algorithm::HS256,
        encode_key: EncodingKey::from_secret(&key),
        sub: Ulid::new().to_string(),
        tenant: Ulid::new().to_string(),
    };

    let mut group = c.benchmark_group("create");

    for config in [rs256, ed_dsa, hs256].iter() {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(config), config, |b, config| {
            b.iter(|| {
                black_box(create_token(&config.encode_key, config.sub.clone(), config.tenant.clone(), expiry_time, config.algorithm));
            });
        });
    }

    group.finish();
}

fn bench_verify_token_asymmetric(c: &mut Criterion) {
    let (private_key, public_key) = generate_rsa_key_pair().unwrap();
    let rsa_private_key = EncodingKey::from_rsa_der(private_key.to_pkcs1_der().unwrap().as_bytes());
    let rsa_public_key = DecodingKey::from_rsa_der(public_key.to_pkcs1_der().unwrap().as_bytes());

    let mut group = c.benchmark_group("verify");

    let rsa = DecodeTokenConfig {
        token: create_token(&rsa_private_key, Ulid::new().to_string().clone(), Ulid::new().to_string().clone(),
                            SystemTime::now().add(Duration::from_secs(3600)).duration_since(UNIX_EPOCH).unwrap().as_secs(), Algorithm::RS256),
        decode_key: rsa_public_key,
        algorithm: Algorithm::RS256,
        validation: Validation::new(Algorithm::RS256),
    };

    let ed_keys = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let ed_dsa_key_pair = Ed25519KeyPair::from_pkcs8(ed_keys.as_ref()).unwrap();
    let ed_dsa = DecodeTokenConfig {
        algorithm: Algorithm::EdDSA,
        decode_key: DecodingKey::from_ed_der(ed_dsa_key_pair.public_key().as_ref()),
        token: create_token(&EncodingKey::from_ed_der(ed_keys.as_ref()), Ulid::new().to_string().clone(), Ulid::new().to_string().clone(),
                            SystemTime::now().add(Duration::from_secs(3600)).duration_since(UNIX_EPOCH).unwrap().as_secs(), Algorithm::EdDSA),
        validation: Validation::new(Algorithm::EdDSA),
    };

    let mut key = [0u8; 128];
    rand::thread_rng().fill(&mut key[..]);
    let hs256 = DecodeTokenConfig {
        token: create_token(&EncodingKey::from_secret(&key), Ulid::new().to_string().clone(), Ulid::new().to_string().clone(),
                            SystemTime::now().add(Duration::from_secs(3600)).duration_since(UNIX_EPOCH).unwrap().as_secs(), Algorithm::HS256),
        decode_key: DecodingKey::from_secret(&key),
        algorithm: Algorithm::HS256,
        validation: Validation::default(),
    };

    for config in [rsa, ed_dsa, hs256].iter() {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(config), config, |b, config| b.iter(|| {
            black_box(decode::<Claims>(config.token.as_str(), &config.decode_key, &config.validation).unwrap());
        }));
    }

    group.finish();
}

criterion_group!(benches, bench_create_token_asymmetric, bench_verify_token_asymmetric);
criterion_main!(benches);

impl Display for CreateTokenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.algorithm.fmt(f)
    }
}

struct DecodeTokenConfig {
    token: String,
    algorithm: Algorithm,
    decode_key: DecodingKey,
    validation: Validation,
}

impl Display for DecodeTokenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.algorithm.fmt(f)
    }
}

fn create_token(key: &EncodingKey, sub: String, tenant: String, expiry_time: u64, algorithm: Algorithm) -> String {
    let my_claims = Claims {
        sub,
        tenant,
        exp: expiry_time,
    };
    encode(&Header::new(algorithm), &my_claims, &key).unwrap()
}

fn generate_rsa_key_pair() -> Result<(RsaPrivateKey, RsaPublicKey), rsa::errors::Error> {
    let bits = 2048;

    let private_key = RsaPrivateKey::new(&mut rand::rngs::OsRng, bits)?;
    let public_key = private_key.to_public_key();

    Ok((private_key, public_key))
}
