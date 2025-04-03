# Design of the Problema Encryption Algorithm

## 1. Design Objectives

1. Modern improvement of Enigma's rotor-based substitution cipher mechanism
2. Utilizing the strengths of AES's Substitution-Permutation Network (SPN) structure
3. Support for multilingual text including Korean and English
4. Providing high encryption strength and complexity
5. Ensuring efficient implementation possibility

## 2. Core Components

### 2.A Enhanced Enigma Mechanism

The core mechanisms of the traditional Enigma have been improved as follows:

1. **Expanded Rotor System**:
   - Use of 8 virtual rotors instead of the traditional Enigma's 3-4 rotors
   - Each rotor contains an expanded substitution table for Unicode character mapping
   - Non-linear improvement of the rotor rotation mechanism to reduce predictability

2. **Multidimensional Plugboard**:
   - Implementation of multidimensional character mapping instead of simple character pair exchanges in the original Enigma
   - Increased complexity through character mapping between Unicode planes
   - Plugboard settings that dynamically change during the encryption process

3. **Reflector Improvements**:
   - Enhanced security by using one-way mapping instead of bidirectional mapping
   - Increased complexity through a multiple reflector system

### 2.B AES Integration Elements

The powerful characteristics of AES are integrated as follows:

1. **SubBytes Transformation**:
   - Extension of AES's S-Box concept applied to Unicode characters
   - Increased confusion through non-linear substitution

2. **ShiftRows and MixColumns Concepts**:
   - Application of row shifting and column mixing operations on character blocks
   - Enhancement of diffusion characteristics

3. **Key Scheduling**:
   - Application of AES-style key expansion algorithm
   - Enhanced security through generation of round-specific subkeys

### 2.C Unicode Processing System

A system for processing various characters including Korean and English:

1. **Unicode Mapping**:
   - Conversion of all input text to Unicode code points
   - Multilingual compatibility through UTF-8 encoding support

2. **Character Set Normalization**:
   - Processing Korean and English characters within the same encryption framework
   - Efficient handling of composite Korean characters

## 3. Encryption Process

The encryption process of the Problema algorithm consists of the following steps:

### 3.A Initialization Phase

1. **Key Setup**:
   - Generation of initial rotor positions, plugboard settings, and AES round keys based on user-provided key
   - Key length set to 256 bits to ensure high security

2. **System Initialization**:
   - Initialization of rotor system, plugboard, and AES components
   - Setting of initial state vector (IV)

### 3.B Encryption Phase

The following process is performed for each character (or character block):

1. **Unicode Conversion**:
   - Converting input characters to Unicode code points
   - Processing Korean and English characters within the same framework

2. **Enigma Phase**:
   - Initial substitution through the enhanced plugboard
   - Continuous substitution through the multi-rotor system
   - Additional substitution through the reflector
   - Reverse rotor passage (asymmetric processing unlike the original Enigma)

3. **AES Phase**:
   - Application of SubBytes transformation to character blocks
   - Application of ShiftRows and MixColumns operations
   - XOR operation with round keys

4. **Feedback Mechanism**:
   - Implementation of a feedback loop where previous output affects the encryption of the next input
   - Creation of block interdependencies to prevent pattern analysis

### 3.C Finalization Phase

1. **Output Encoding**:
   - Encoding encrypted data in specified format (Base64, hexadecimal, etc.)
   - Addition of metadata (version, settings used, etc.)

## 4. Decryption Process

The decryption process proceeds in reverse order of encryption and has the following characteristics:

1. **Symmetry**:
   - Performing encryption and decryption using the same key
   - Exact reverse application of encryption steps

2. **State Restoration**:
   - Accurate restoration of initial states used during encryption
   - Precise reproduction of rotor positions, plugboard settings, etc.

## 5. Security Characteristics

The Problema algorithm provides the following security features:

1. **High Entropy**:
   - Resistance to brute force attacks with a 256-bit key space
   - Prevention of statistical analysis through non-linear operations

2. **Confusion and Diffusion**:
   - Utilization of AES's powerful confusion and diffusion characteristics
   - Small changes in input causing large changes in output

3. **Defense Against Known Attacks**:
   - Resistance to modern attack techniques such as differential cryptanalysis and linear cryptanalysis
   - Mitigation of historical vulnerabilities in Enigma

## 6. Performance Considerations

1. **Computational Efficiency**:
   - Possibility of efficient implementation through optimized operations
   - Consideration of hardware acceleration possibilities

2. **Memory Requirements**:
   - Memory optimization for expanded rotors and S-Boxes
   - Design of cache-friendly data structures

## 7. Implementation Guidelines

Implementation in C language with the following considerations:

1. **Modularity**:
   - Separation of modules by core components
   - Design considering maintainability and scalability

2. **Optimization**:
   - Optimization of performance-critical parts
   - Utilization of bit operations and lookup tables

3. **Testing**:
   - Thorough testing for various inputs
   - Special testing for mixed Korean and English text