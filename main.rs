use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce
};
use rand::Rng;
use argon2::{self, Argon2, PasswordHasher, password_hash::SaltString};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::fs;
use std::io::{self, Write};
use std::env;
use std::path::Path;

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();

    // Convert salt to a SaltString using the new method
    let salt_string = STANDARD.encode(salt);
    let salt = SaltString::new(&salt_string).unwrap();

    // Hash the password
    let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();

    // Get the hash bytes
    let hash_bytes = password_hash.hash.unwrap();

    // Create a key from the hash output
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_bytes.as_bytes()[..32]); // Ensure key fits into 32 bytes
    key
}

fn encrypt_file(file_path: &str, password: &str) -> io::Result<()> {
    let contents = fs::read(file_path)?;

    // Generate a random salt and nonce
    let salt: [u8; 16] = rand::thread_rng().gen();
    let key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(&key.into());

    let nonce = Nonce::from(rand::thread_rng().gen::<[u8; 12]>()); // 96-bit nonce
    let ciphertext = cipher.encrypt(&nonce, contents.as_ref())
        .expect("Encryption failure!");

    // Store salt, nonce, and ciphertext together
    let mut encrypted_data = Vec::new();
    encrypted_data.extend_from_slice(&salt);
    encrypted_data.extend_from_slice(nonce.as_slice());
    encrypted_data.extend_from_slice(&ciphertext);

    let encoded = STANDARD.encode(&encrypted_data);
    let mut output_file = fs::File::create(format!("{}.enc", file_path))?;
    output_file.write_all(encoded.as_bytes())?;
    println!("File encrypted and saved as {}.enc", file_path);
    Ok(())
}

fn decrypt_file(file_path: &str, password: &str) -> io::Result<()> {
    let encoded_data = fs::read_to_string(file_path)?;
    let encrypted_data = STANDARD.decode(encoded_data.as_bytes()).expect("Decoding failed");

    // Extract salt, nonce, and ciphertext
    let salt = &encrypted_data[..16];
    let nonce = Nonce::from_slice(&encrypted_data[16..28]); // 96-bit nonce
    let ciphertext = &encrypted_data[28..];

    let key = derive_key(password, salt);
    let cipher = ChaCha20Poly1305::new(&key.into());

    let decrypted_data = cipher.decrypt(nonce, ciphertext.as_ref())
        .expect("Decryption failure!");

    let output_path = Path::new(file_path).file_stem().unwrap().to_str().unwrap();
    let mut output_file = fs::File::create(output_path)?;
    output_file.write_all(&decrypted_data)?;
    println!("File decrypted and saved as {}", output_path);
    Ok(())
}

// Main function remains unchanged
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: {} <encrypt|decrypt> <file_path> <password>", args[0]);
        return;
    }

    let command = &args[1];
    let file_path = &args[2];
    let password = &args[3];

    match command.as_str() {
        "encrypt" => encrypt_file(file_path, password).unwrap(),
        "decrypt" => decrypt_file(file_path, password).unwrap(),
        _ => eprintln!("Unknown command: {}", command),
    }
}
