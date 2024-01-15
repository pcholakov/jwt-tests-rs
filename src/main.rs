use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, decode, DecodingKey, encode, EncodingKey, Header, Validation};
use ring::signature::{Ed25519KeyPair, KeyPair};
use ulid::Ulid;

use jwt_tests::Claims;

fn main() {
    let claims = Claims {
        sub: Ulid::new().to_string(),
        tenant: Ulid::new().to_string(),
        exp: SystemTime::now().add(Duration::from_secs(3600)).duration_since(UNIX_EPOCH).unwrap().as_secs(),
    };

    // let private_key = EncodingKey::from_rsa_pem(include_bytes!("private.pem")).unwrap();
    // let public_key = DecodingKey::from_rsa_pem(include_bytes!("public.pem")).unwrap();
    let ed_key_doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(ed_key_doc.as_ref()).unwrap();

    // let token = encode(&Header::new(Algorithm::RS256), &claims, &private_key).unwrap();
    let token = encode(&Header::new(Algorithm::EdDSA), &claims, &EncodingKey::from_ed_der(ed_key_doc.as_ref())).unwrap();
    println!("Token: {}", token);

    // let token = decode::<Claims>(token.as_str(), &public_key, &Validation::new(Algorithm::RS256)).unwrap();
    let token = decode::<Claims>(token.as_str(), &DecodingKey::from_ed_der(pair.public_key().as_ref()), &Validation::new(Algorithm::EdDSA)).unwrap();
    println!("{:?}", token.claims);
}
