# tencryptor

## Project Overview

Tosan Encryptor is a Java library providing basic encryption utilities. It uses Bouncy Castle for cryptographic operations and supports multiple encryption algorithms including AES with PKCS5/PKCS7 padding, and ECDH encryption.

## Build and Test Commands

```bash
# Build the project
mvn clean package

# Run all tests
mvn test

# Run a specific test class
mvn test -Dtest=TosanEncryptorUTest

# Run a specific test method
mvn test -Dtest=TosanEncryptorUTest#testEncryptionProcess_encryptWithDefaultAlgorithm_encrypted

# Generate Javadoc
mvn javadoc:javadoc

# Install to local Maven repository
mvn install
```

## Architecture

### Core Components

The library is organized into four main packages:

**`com.tosan.tools.tencryptor.encryptor`**: Entry point for encryption/decryption operations
- `Encryptor` (interface): Defines the contract for encryption operations
- `TosanEncryptor`: Main implementation supporting multiple algorithms via strategy pattern

**`com.tosan.tools.tencryptor.algorithm`**: Encryption algorithm implementations (strategy pattern)
- `AlgorithmEncryption` (interface): Contract for algorithm implementations
- `DefaultAlgorithmEncryption`: PKCS5 padding implementation
- `DynamicAlgorithmEncryptionWithIV`: PKCS7 padding with dynamic IV
- `GenericAlgorithmEncryption`: Generic algorithm support

**`com.tosan.tools.tencryptor.util`**: Utility classes for common operations
- `EncryptionUtil`: AES encryption/decryption, ECDH operations, and hash generation
- `HashUtil`: SHA-2 hashing with salt and HMAC generation using Bouncy Castle
- `ECDHEncryptionUtil`: Elliptic Curve Diffie-Hellman encryption
- `EncryptionStringUtil`: String manipulation utilities for encryption

**`com.tosan.tools.tencryptor.exception`**: Custom exceptions
- `EncryptionException`: Base exception for encryption errors
- `InvalidKeyException`: Thrown for invalid encryption keys
- `InvalidAlgorithmException`: Thrown for unsupported algorithms
- `InvalidValueException`: Thrown for invalid input values

### Key Design Patterns

**Strategy Pattern**: `TosanEncryptor` delegates to `AlgorithmEncryption` implementations based on the algorithm specified at construction time. The algorithm map is populated in the constructor.

**Algorithm Selection**: Algorithms are selected at instantiation:
- Default: `PKCS5_ALGORITHM` ("AES/CBC/PKCS5Padding") → uses `DefaultAlgorithmEncryption`
- `PKCS7_ALGORITHM` ("AES/CBC/PKCS7Padding") → uses `DynamicAlgorithmEncryptionWithIV`
- Other algorithms → uses `GenericAlgorithmEncryption`

### Encryption Flow

1. User creates `TosanEncryptor` with key and optional algorithm
2. Constructor creates `SecretKeySpec` and selects appropriate `AlgorithmEncryption` implementation
3. `encryptText()` delegates to the algorithm implementation, then Base64 encodes result
4. `decryptText()` Base64 decodes, then delegates to algorithm implementation

## Release Process

The project uses maven-release-plugin with the following configuration:
- Tag format: `v{project.version}` (e.g., v1.0.0)
- Release profile for GitHub Packages deployment
- Build profile for Maven Central with GPG signing


## Important Notes

- Target Java version: 8
- Uses Bouncy Castle `bcprov-jdk18on`
- Tests use JUnit Jupiter
- Default encryption algorithm is AES/CBC/PKCS5Padding with 128-bit keys
