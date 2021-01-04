#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <inttypes.h>

#define DATA_SIZE 65536		// 1 MB message size
#define HASH_SIZE 32		// 256 bit hash from SHA-256
#define MAC_SIZE 32		// 256 bit MAC from HMAC-SHA-256
#define CIPHER_SIZE 128
#define SIGNATURE_SIZE 128	// RSA 1024 bit test key
// #define SIGNATURE_SIZE 96	// 768 bit signature from curve P-384
#define MAC_SIZE 32		// HMAC-SHA-256
#define ID_SIZE 30
#define PIN_SIZE 5
#define KEY_SIZE 16		// Symmetric key size - 256 + 128 bits
#define ECC_KEY_SIZE 384	// ECC 384 bit keys
// #define PUB_KEY_SIZE 786	// ECC 768 bit public keys
#define PUB_KEY_SIZE 1024	// ECC 768 bit public keys
// For RSA ciphertext size is the size of the key 1024 bits - 1024/8 bytes ciphertext

// Authentication request, response structures
struct auth_request {
	uint8_t pin[PIN_SIZE];
};

struct auth_reponse {
};
// ----------------------

// Change authentication PIN request, response structures
struct admin_request {
	uint8_t pin[PIN_SIZE];
};

struct admin_reponse {
};
// ----------------------

// Data encryption/decryption request, response structures
struct data_request {
	uint8_t key_id[ID_SIZE];		// Id of symmetric key to encrypt data
	uint16_t data_size;
	uint8_t data[DATA_SIZE];
};

struct data_response {
	uint16_t data_size;
	uint8_t data[DATA_SIZE];
};
// ----------------------

// Generate Symmetric key request, response structures
struct gen_key_request {
	uint8_t entity_id[ID_SIZE];	// Id of entity to share generated symmetric key
	uint8_t key_id[ID_SIZE];		// Id of new symmetric key to generate
};

struct gen_key_response {
	// size_t msg_size;		// Size of message with encrypted key
	uint8_t msg[CIPHER_SIZE+SIGNATURE_SIZE];	// Generated encrypted and signed symmetric key
	uint8_t key_id[ID_SIZE];		// Id of generated key
};
// ----------------------

// Save Symmetric key request, response structures
struct save_key_request {
	uint8_t msg[CIPHER_SIZE+SIGNATURE_SIZE];	// Encrypted and signed key
	uint8_t entity_id[ID_SIZE];	// Id of entity who sent the symmetric key
	uint8_t key_id[ID_SIZE];		// Id of symmetric key to encrypt data
};

struct save_key_response {
};
// ----------------------

// Sign document request, response structures
struct sign_request {
	uint16_t data_size;
	uint8_t data[DATA_SIZE];		// Data to be signed
};

struct sign_response {
	uint8_t signature[SIGNATURE_SIZE];	// Generated signature
};
// ----------------------

// Verify document signature request, response structures
struct verify_request {
	uint8_t signature[SIGNATURE_SIZE];	// Data signature
	uint8_t entity_id[ID_SIZE];		// ID of entity who signed the data
	uint16_t data_size;
	uint8_t data[DATA_SIZE];		// Data signed
};

struct verify_response {
};
// ----------------------

// Import public key request, response structures
struct import_pub_request {
	uint8_t entity_id[ID_SIZE];		// ID of entity
	uint8_t public_key[PUB_KEY_SIZE];	// Public key of the entity
	uint16_t cert_size;
};

struct import_pub_response {
};
// ----------------------

// List keys request, response structures
struct list_keys_request {
};

struct list_keys_response {
	uint8_t list[DATA_SIZE];		// List of keys
};
// ----------------------

// Main request structure with base parameters (op_code, status) and
// union structures, only one is used, depending on the operation
struct request {
	uint8_t op_code;		// Operation Code

	union {
		struct auth_request auth;
		struct admin_request admin;
		struct data_request data;
		struct gen_key_request gen_key;
		struct save_key_request save_key;
		struct sign_request sign;
		struct verify_request verify;
		struct import_pub_request import_pub;
		struct list_keys_request list;
	};
};

// Main response structure with base parameters (op_code, status) and
// union structures, only one is used, depending on the operation
struct response {
	uint8_t op_code;		// Operation Code
	uint8_t status;		// Operation Status

	union {
		struct auth_reponse auth;
		struct admin_reponse admin;
		struct data_response data;
		struct gen_key_response gen_key;
		struct save_key_response save_key;
		struct sign_response sign;
		struct verify_response verify;
		struct import_pub_response import_pub;
		struct list_keys_response list;
	};
};

#endif 
