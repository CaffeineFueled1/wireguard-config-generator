# WireGuard Configuration Generator

A web-based tool for generating WireGuard VPN configurations with cryptographically secure key generation. Supports both **Hub-and-Spoke** and **Mesh Network** topologies.

## TODO

- QR Code generator for config
- Download all config at once
- Make `PresharedKey` and other options optional
- Container
- frontend rework (I hate frontend)

## 🔐 Cryptography

This project uses **real cryptographic implementations** suitable for WireGuard deployments, not demonstration code.

### Cryptographic Implementation

#### **Libraries Used**
- **[TweetNaCl.js v1.0.3](https://tweetnacl.js.org/)** - Audited, lightweight cryptographic library
- **Web Crypto API** - Browser-native cryptographic operations when available
- **HMAC-SHA256 Fallback** - Custom implementation for browsers without Web Crypto API

#### Cryptographic Flow

1. **Seed Generation/Input**
   - Generate cryptographically secure 32-byte seed
   - Or accept user-provided hex seed for reproducibility

2. **Key Derivation**
   - Use HKDF to derive keys from seed with unique salts
   - Private keys: `HKDF(seed, "WireGuard v1 private key", key_index)`
   - Preshared keys: `HKDF(seed, "WireGuard v1 preshared key", key_index)`

3. **Public Key Generation**
   - Apply Curve25519 scalar multiplication: `public = private * G`
   - Where G is the Curve25519 base point

4. **Key Validation**
   - Verify key lengths (32 bytes each)
   - Check private key clamping
   - Confirm public key derivation

# License

MIT License
