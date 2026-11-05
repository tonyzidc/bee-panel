use rand::Rng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

#[test]
fn test_ed25519_ssh_keygen() {
    let mut rng = rand::thread_rng();
    let private_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("Should generate Ed25519 key");

    let pem = private_key.to_openssh(LineEnding::LF).expect("Should encode to OpenSSH PEM");
    assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert!(pem.trim().ends_with("-----END OPENSSH PRIVATE KEY-----"));

    let pubkey = private_key.public_key().to_openssh().expect("Should encode public key");
    assert!(pubkey.starts_with("ssh-ed25519 "));
}

#[test]
fn test_password_generation_length_and_charset() {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut rng = rand::thread_rng();
    let len = 16;
    let password: String = (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    assert_eq!(password.len(), 16);
}
