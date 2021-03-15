# Secure Message Exchange Protocol

This repository contains a local implementation of my thesis work.

It emulates two programs:
- HSM application with all cryptographic services;
- User interface, with a PKCS#11 API which calls the HSM services.

## HSM Services
- Message Exchange with authentication, integrity and confidentiality services;
- ECDSA digital signatures;
- ECDH key generation and derivation;
- Secure Key importation.

## Implementation

The program is composed of two components.
* The user application running on the user's computer.
* The API wich performs the cryptographic operations, running on the secure device.

The harware connection between both components is emulated with a named pipe.

### Requirements
* gcc version 10.2.1
* OpenSSL version 1.1.1i
* mbedtls versoin 2.25.0

### References
* Diogo Parrinha and Ricardo Chaves previous [work](http://sips.inesc-id.pt/~rjfc/cores/HSM-SF2/)
* PKCS#11 [Library](https://github.com/Pkcs11Interop/empty-pkcs11)

## Thesis: Hardware-Secured System for Secure Communications and Message Exchange

>__Abstract.__ Individuals with high responsibility jobs such as government officials, top level company executives and diplomats are high profile targets to digital attacks. These individuals handle very sensitive information. Thus, attacks can have very damaging consequences for them and organizations. It is unsafe for them to store cryptographic keys, passwords and perform critical cryptographic operations with their personal computers. This thesis proposes a cheap, relatively efficient but highly secure physical personal system, in a client-server mode, which enables individuals to securely exchange messages and sensitive documents. The proposed system secures communication by providing confidentiality and authentication to messages. This system will be responsible for performing every cryptography operation, store and manage cryptographic keys. All operations are performed inside the device and keys are never exposed to the outside, in order to not jeopardize the security of the communications.
