# Secure Message Exchange Protocol

This repository contains an initial implementation for my thesis project.

## Thesis: Hardware-Secured System for Secure Communications and Message Exchange

>__Abstract.__ Individuals with high responsibility jobs such as government officials, top level company executives and diplomats are high profile targets to digital attacks. These individuals handle very sensitive information. Thus, attacks can have very damaging consequences for them and organizations. It is unsafe for them to store cryptographic keys, passwords and perform critical cryptographic operations with their personal computers. This thesis proposes a cheap, relatively efficient but highly secure physical personal system, in a client-server mode, which enables individuals to securely exchange messages and sensitive documents. The proposed system secures communication by providing confidentiality and authentication to messages. This system will be responsible for performing every cryptography operation, store and manage cryptographic keys. All operations are performed inside the device and keys are never exposed to the outside, in order to not jeopardize the security of the communications.

## Implementation

The program is composed of two components.
* The client application running on the user's computer.
* The API wich performs the cryptographic operations, running on the secure device.

The harware connection between both components is emulated through a named pipe.

### Requirements
* C language
* OpenSSL library
