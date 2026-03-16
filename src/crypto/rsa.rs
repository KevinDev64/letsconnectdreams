use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey,EncodeRsaPrivateKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

pub fn generate_rsa_keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 3072)
        .expect("Failed to generate RSA keypair!");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

pub fn rsa_encrypt_message(public_key: &RsaPublicKey, message: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    public_key.encrypt(&mut rng, Pkcs1v15Encrypt, message)
        .expect("Failed to encrypt message!")
}

pub fn rsa_decrypt_message(private_key: &RsaPrivateKey, message: &[u8]) -> Vec<u8> {
    private_key.decrypt(Pkcs1v15Encrypt, message)
        .expect("Failed to decrypt message!")
}

pub fn get_rsa_keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let priv_key = match RsaPrivateKey::read_pkcs1_pem_file("priv_key.pem") {
        Ok(key) => key,
        Err(e) => {
            println!("Private key file not found! {e}");
            let (priv_key, _pub_key) = generate_rsa_keypair();
            priv_key.write_pkcs1_pem_file("priv_key.pem", rsa::pkcs8::LineEnding::LF)
                .expect("Failed to write private key file!");
            priv_key
        }
    };
    let pub_key = priv_key.to_public_key();
    (priv_key, pub_key)
}