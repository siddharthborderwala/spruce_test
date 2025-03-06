# Spruce Test - Verifiable Credentials Demo

This project demonstrates a simple verifiable credentials system using RSA cryptography and JWTs. It consists of three main components:

1. **Key Generator** - Generates RSA key pairs for the holder
2. **Holder** - Creates and signs attestations using private keys
3. **Verifier** - Verifies signed attestations using public keys

## Architecture

```
┌─────────────────────────────────────────┐      ┌─────────────────────────┐
│              Client Side                │      │       Server Side       │
│                                         │      │                         │
│  ┌─────────────┐       ┌─────────────┐  │      │     ┌─────────────┐     │
│  │             │       │             │  │      │     │             │     │
│  │   KeyGen    │──────▶│   Holder    │  │      │     │  Verifier   │     │
│  │             │       │             │  │      │     │             │     │
│  └─────────────┘       └──────┬──────┘  │      │     └──────┬──────┘     │
│                               │         │      │            │            │
└───────────────────────────────┼─────────┘      └────────────┼────────────┘
                                │                             │
                                │                             │
                                │         1. Request Nonce    │
                                ├────────────────────────────▶│
                                │                             │
                                │         2. Return Nonce     │
                                │◀────────────────────────────┤
                                │                             │
                                │    3. Register Public Key   │
                                ├────────────────────────────▶│
                                │                             │
                                │    4. Send Signed JWT       │
                                ├────────────────────────────▶│
                                │                             │
                                │    5. Verification Result   │
                                │◀────────────────────────────┤
```

## Components

### Key Generator (`keygen`)
Generates RSA key pairs and stores them in the configured keys directory in JSON format.

### Holder (`holder`)
- Requests a nonce from the verifier
- Prompts the user for a message to attest to
- Signs the message and nonce using the private key
- Sends the signed JWT to the verifier for verification

### Verifier (`verifier`)
- Provides nonces to holders
- Stores public keys for verification
- Verifies signed JWTs from holders
- Returns verification results

## Getting Started

### Prerequisites
- Rust and Cargo installed
- SQLite

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/spruce_test.git
cd spruce_test
```

2. Build the project:
```bash
cargo build
```

### Running the Components

1. **Start the Verifier**:
```bash
cargo run --bin verifier
```
The verifier will start on http://127.0.0.1:3000 by default. It will store registerd public keys and used nonces in an sqlite database.

2. **Generate Keys**:
```bash
cargo run --bin keygen
```
This will generate RSA key pairs in the configured keys directory. This will also register the public key with the verifier.

3. **Run the Holder**:
```bash
cargo run --bin holder
```

The holder will:
- Connect to the verifier
- Request a nonce
- Prompt for a message (or use the default)
- Sign the message
- Send it to the verifier for verification

## Configuration

The application uses environment variables for configuration:

- `KEYS_DIRECTORY` - Directory for storing keys (default: `./keys`)
- `DB_PATH` - Path to the SQLite database (default: `./storage.db`)
- `VERIFIER_URL` - URL of the verifier service (default: `http://127.0.0.1:3000`)

## Security

Read the [SECURITY.md](SECURITY.md) file for more information.

## API Endpoints

The verifier exposes the following API endpoints:

- `POST /api/nonce` - Request a new nonce
- `POST /api/keys` - Register a public key
- `GET /api/keys` - List registered public keys
- `DELETE /api/keys/:kid` - Delete/deactivate a public key
- `POST /api/verify` - Verify a signed JWT to check private key ownerhip

### Testing

Run the tests with:
```bash
cargo test
```
