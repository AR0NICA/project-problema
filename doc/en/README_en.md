# Detailed Overview of the Problema Encryption Algorithm

## Overview

Problema is a hybrid encryption algorithm named after the Latin word "Probléma" (meaning "problem" or "challenge"). It combines the conceptual elegance of the historical Enigma encryption system with the security features of AES (Advanced Encryption Standard), widely regarded as one of the most robust algorithms in modern cryptography. A standout feature of Problema is its ability to effectively encrypt and decrypt text that mixes Korean and English characters.

This document provides an in-depth explanation of the Problema algorithm’s working principles, components, and encryption/decryption processes.
Note that this algorithm was developed as an educational exercise by a student majoring in security and is **not recommended for actual use.**

## References

The design principles of the Problema algorithm are explained in detail here:
- [Design of the Problema](problema_design_en.md)

Since Problema is not fully implemented, several issues remain. Please refer to the following document for details:
- [Problema Improvement Report](improvement_report_en.md)
  
## 0. Introduction

### 0.A How to Use the Problema Algorithm
```bash
# Compile
make

# Encrypt
./problema -e -k "secret_key" "text_to_encrypt"

# Encrypt with verbose output
./problema -e -k "secret_key" -v "text_to_encrypt"

# Decrypt
./problema -d -k "secret_key" "encrypted_text"

# Help
./problema --help
```

### 0.B Encryption Process and Result
```bash
ubuntu@ar0nica:~/project_problema $ cd /home/ubuntu && cd /home/ubuntu/problema_project && ./problema -e -k "secret_key" -v "나의 life는 like a 천국이다"
[DEBUG] Debug mode activated
Encryption mode
[DEBUG] UTF-8 → Unicode conversion: 34 bytes → 20 characters
[DEBUG] Character before encryption: U+B098 (나)
[DEBUG] After plugboard: U+B098
[DEBUG] After forward rotor: U+AFEA
[DEBUG] Rotor rotation state: 137 214 95 129 214 55 210 237
[DEBUG] After reverse rotor: U+AE7D
[DEBUG] Encrypted character: U+AE7D
[DEBUG] Character before encryption: U+C758 (의)
[DEBUG] After plugboard: U+C758
[DEBUG] After forward rotor: U+C380
[DEBUG] Rotor rotation state: 138 214 95 129 214 55 210 237
[DEBUG] After reverse rotor: U+C76F
[DEBUG] Encrypted character: U+6912
[DEBUG] Character before encryption: U+0020 (space)
[DEBUG] After plugboard: U+0020
[DEBUG] After forward rotor: U+FE70
[DEBUG] Rotor rotation state: 139 214 95 129 214 55 210 237
[DEBUG] After reverse rotor: U+00CB
[DEBUG] Encrypted character: U+69D9
...

[Encryption Process]
Input text (UTF-8): EB 82 98 EC 9D 98 20 6C 69 66 65 EB 8A 94 20 6C 69 6B 65 20 61 20 EC B2 9C EA B5 AD EC 9D B4 EB 8B A4
Unicode conversion (UTF-8 → code points):
U+B098 (나) → U+C758 (의) → U+0020 ( ) → U+006C (l) → U+0069 (i) → U+0066 (f) → U+0065 (e) → U+B294 (는) → U+0020 ( ) → U+006C (l) → U+0069 (i) → U+006B (k) → U+0065 (e) → U+0020 ( ) → U+0061 (a) → U+0020 ( ) → U+CC9C (천) → U+AD6D (국) → U+C774 (이) → U+B2E4 (다)
Rotor and plugboard processing:
- Plugboard substitution
- Forward pass through 8 rotors
- Rotor rotation
- Reverse pass through 8 rotors
- AES transformation applied
Encrypted output (UTF-8): EA B9 BD E6 A4 92 E6 A7 99 E6 A1 85 E6 A7 8A E9 98 A5 E6 A7 8B ED AB 8B E2 90 8D E2 90 AB E2 92 9C E2 90 BD ED AF A7 ED AA A1 ED AC B0 ED A9 A0 E1 87 93 EB B8 BE E7 A5 B4 EC AF A2
[DEBUG] Problema context released
```

**Note**: The input text "나의 life는 like a 천국이다" mixes Korean and English, translating to "My life is like a paradise" in English.

## 1. Development Background and Inspiration

### 1.A Characteristics of Enigma

Enigma was an encryption machine used by the German military during World War II, considered highly complex and secure for its time. Its core mechanisms include:

- **Rotor System**: Substitutes characters via multiple rotating disks (rotors)
- **Plugboard**: An additional substitution step swapping character pairs
- **Reflector**: Reflects signals back through the rotors in reverse

Enigma’s weaknesses stemmed from operational practices and design limitations, such as the inability of a character to encrypt to itself.

### 1.B Modern Strengths of AES

AES, standardized by the National Institute of Standards and Technology (NIST) in 2001, is a modern encryption algorithm with these features:

- **Substitution-Permutation Network (SPN)**: Iterates non-linear substitutions (S-Box) and linear transformations
- **Round-Based Structure**: Ensures high security through multiple transformation rounds
- **Key Scheduling**: Derives subkeys for each round from an initial key

## 2. Core Features of the Problema Algorithm

Problema merges the strengths of Enigma and AES, introducing innovative elements:

### 2.A Extended Unicode-Based Rotor System

Unlike Enigma’s 26-alphabet limit, Problema uses a virtual rotor system to process the full Unicode character set:

- **Multi-Plane Unicode Processing**: Supports various Unicode planes, including the Basic Multilingual Plane (BMP)
- **Dynamic Rotor Mapping**: Generates rotor mappings dynamically based on the key
- **Non-Linear Rotation Mechanism**: Employs complex rotation patterns instead of a simple odometer approach

### 2.B Multi-Dimensional Character Mapping

Problema goes beyond 1:1 substitution with multi-dimensional character mapping:

- **Context-Dependent Substitution**: Adjusts substitution based on previous characters and current state
- **Hierarchical Mapping**: Applies distinct transformations to different parts (bit groups) of character code points
- **Variable Length Processing**: Efficiently handles variable-length encodings like UTF-8

### 2.C AES-Inspired Block Transformations

Leverages AES’s strong confusion and diffusion properties:

- **Extended S-Box**: A non-linear substitution table for Unicode characters
- **Block-Based Processing**: Processes character blocks rather than individual characters
- **Multi-Round Transformations**: Enhances security through repeated transformations

## 3. Detailed Algorithm Structure

### 3.A Data Representation and Processing

Problema processes input text as follows:

1. **Unicode Conversion**: Converts all input characters to Unicode code points
2. **Block Construction**: Groups code points into 128-bit (16-byte) blocks
3. **Padding**: Applies PKCS#7-compatible padding to the final block if needed

### 3.B Key Processing System

Problema’s key system is structured as follows:

1. **Master Key**: A user-supplied 256-bit (32-byte) key
2. **Key Expansion**: Derives subkeys from the master key for:
   - Rotor initial state
   - Plugboard configuration
   - AES round keys
   - Feedback mechanism
  
### 3.C Detailed Encryption Process

Each block’s encryption follows these stages:

#### 3.C.a Initial Transformation Stage

1. **Initial XOR**: XORs the input block with a key-derived value
2. **Plugboard Transformation**: Performs initial substitution via a multi-dimensional mapping table

#### 3.C.b Rotor Stage

1. **Forward Rotor Pass**: Passes through 8 virtual rotors sequentially
   - Each rotor applies a substitution table to Unicode code points
   - Rotors rotate after each character (following a non-linear pattern)
2. **Intermediate Transformation**: Applies a non-linear transformation via an AES-inspired S-Box
3. **Reverse Rotor Pass**: Passes through a different rotor set with unique rotation patterns in reverse

#### 3.C.c AES-Inspired Transformation Stage

1. **SubBytes**: Applies non-linear S-Box transformations to each byte
2. **ShiftRows**: Cyclically shifts rows within the block
3. **MixColumns**: Mixes columns using Galois field operations
4. **AddRoundKey**: XORs with the round key

#### 3.C.d Feedback and Finalization Stage

1. **State Update**: The current block’s result influences the next block’s processing
2. **Final Transformation**: Applies additional non-linear transformations and key mixing

### 3.D Decryption Process

Decryption reverses the encryption process exactly:

1. **Reverse Final Transformation**
2. **Reverse AES Transformation**:
   - Inverse AddRoundKey
   - Inverse MixColumns
   - Inverse ShiftRows
   - Inverse SubBytes
3. **Reverse Rotor Processing**:
   - Passes through rotors in the exact reverse order of encryption
   - Applies the correct reverse rotation pattern
4. **Reverse Plugboard and Initial Transformation**

## 4. Korean and English Processing Mechanism

One of the core features of Problema is its efficient handling of multilingual text, including mixed Korean and English content:

### 4.A Unicode Processing Optimization

1. **UTF-8 Encoding Recognition**: Efficiently processes UTF-8 encoded input text
2. **Code Point Normalization**: Handles normalization processes like Korean syllable composition
3. **Character Boundary Recognition**: Recognizes boundaries of variable-length characters for processing

### 4.B Korean-Specific Processing

1. **Composite Korean Character Handling**: Processes complete Korean syllables in Unicode range U+AC00~U+D7A3
2. **Decomposed Korean Support**: Supports Korean jamo components (U+1100~U+11FF, U+3130~U+318F) when needed
3. **Korean Characteristics Consideration**: Enhances encryption by considering statistical characteristics of Korean

### 4.C Mixed Text Processing

1. **Language Boundary Transparency**: Seamlessly processes text mixing Korean and English
2. **Consistent Security Strength**: Maintains uniform security level across all character types
3. **Context-Aware Encryption**: Considers contextual relationships between characters during encryption

## 5. Security Analysis

### 5.A Cryptographic Strength

Problema provides the following cryptographic strengths:

1. **Key Space**: 256-bit key space offering 2^256 possible key combinations
2. **Non-linearity**: High non-linearity through multiple S-Boxes and complex transformations
3. **Diffusion Properties**: Strong diffusion where small input changes affect the entire output

### 5.B Resistance to Known Attacks

1. **Differential Cryptanalysis**: High resistance due to multiple rounds and non-linear transformations
2. **Linear Cryptanalysis**: Defense through complex key scheduling and non-linear S-Boxes
3. **Related-Key Attacks**: Protected by robust key scheduling algorithms
4. **Side-Channel Attacks**: Implementation-level countermeasures should be considered

### 5.C Improvements over Enigma Vulnerabilities

1. **Self-Encryption Removal**: Designed to allow characters to encrypt to themselves, unlike Enigma
2. **Deterministic Pattern Elimination**: Removes predictable patterns present in Enigma
3. **Key Management Enhancement**: Introduces robust key management systems

## 6. Performance and Implementation Considerations

### 6.A Computational Complexity

1. **Time Complexity**: O(n) - linear with respect to input size
2. **Space Complexity**: Fixed memory requirements for rotor tables and S-Boxes

### 6.B Optimization Strategies

1. **Lookup Tables**: Pre-computed tables for frequently used transformations
2. **Parallel Processing**: Possibility for parallel processing of independent blocks
3. **Hardware Acceleration**: Potential for hardware acceleration of specific operations

### 6.C Implementation Recommendations

1. **Modularity**: Separation of functions into modules for improved maintainability
2. **Secure Coding**: Prevention of vulnerabilities like buffer overflows
3. **Test Vectors**: Provision of test vectors for algorithm verification

## 7. Application Scenarios

Problema is expected to be suitable for the following application areas:

1. **Multilingual Document Encryption**: Secure storage of documents mixing Korean and English
2. **Communication Security**: Secure transmission of multilingual messages
3. **Database Encryption**: Field-level encryption of multilingual data
4. **Education and Research**: Research on connections between modern cryptography and historical cipher systems

## 8. Conclusion

The Problema encryption algorithm combines the conceptual elegance of the historical Enigma with the robust security features of modern cryptography to provide a new encryption solution that works effectively in multilingual environments. This algorithm was designed with the aim of presenting an innovative approach valuable for both academic interest and practical applications.

Problema goes beyond being a simple encryption tool – it uniquely narrates the fusion of cryptographic history and modern technology.