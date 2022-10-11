# CryptoLibC
Crypto authentication functions for use with atecc devices, more specifically for the ATECC608A, although is also compatible with previous versions of this cryptoprocessors family like ATECC508A.  

This small software library includes different programs that will allow you to:
* Generate random numbers.
* Use of symmetric encryption/decryption algorithms like AES and its differente modes of operation (CBC, CBCMAC, CMAC, CCM, GCM and CTR).
* Use of asymmetric encryption/decryption algorithms like Elliptic Curve Diffe-Helmman (ECDH).
* Generation of hash coodes.
* Sign and verification of digital signatures.
* Derivation keys methods like pbkdf2.
* Read and write operations in the data zone of the cryptoprocessor.
* Manipulation and generation of cryptographic keys in the cryptoprocessor.

It will be of interest in the future to add some new functionalities:
* Creation and manipulation of X.509 certificates.
* Implementation of the secure boot functionality.
* Add more key derivation functions such as: MAC, HMAC and KDF.

# Test
There is a test folder that includes two C programs and one bash program.
The C programs are designed to test the common functionality by testing different parameters and execution cases.
The bash program is designed to test the different execution of all programs designed.
The main objective of this programs is to ensure that modifications on the programs don't disrupt the flow of operation and the expected results.

# Performance
This folder includes implementations of the AES-128 and SHA-2 algorithm in order to compare the execution times with the ones 
of the cryptoprocessor, it also includes different size files for the comparation (200, 1000 and 5000 bytes size).
