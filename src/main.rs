const MSG: &str = r#"
Key Ownership Verification Service
=================================
This project contains two binaries:
1. Verifier: A web service that verifies key ownership
2. Holder: A client that signs payloads with a private key

To run keygen:
  cargo run --bin keygen

To run the verifier web server:
  cargo run --bin verifier

To run the holder client script:
  cargo run --bin holder

See README.md for more details.
"#;

fn main() {
    println!("{}", MSG);
}
