#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <inttypes.h>

#define DATA_SIZE 65536		// 1 MB message size
#define HASH_SIZE 32		// 256 bit hash from SHA-256
#define MAC_SIZE 32		// 256 bit MAC from HMAC-SHA-256
#define KEY_SIZE 16		// Symmetric key size - 256 + 128 bits
#define ECC_KEY_SIZE 384	// ECC 384 bit keys
#define PUB_KEY_SIZE 1024	// ECC 768 bit public keys
#define SALT_SIZE 16		// Salt size - 16 bytes

#define SIGNATURE_SIZE 128	// MAX SIZE 1024 bit test key
#define ID_SIZE 30
#define PIN_SIZE 6

// Authentication request, response structures
struct auth_request {
	uint8_t pin[PIN_SIZE];
};

// Change authentication PIN request, response structures
struct admin_request {
	uint8_t pin[PIN_SIZE];
};
// ----------------------


// Data encryption/decryption request, response structures
struct data_request {
	uint8_t key_id[ID_SIZE];		// Id of symmetric key to encrypt data
	uint64_t data_size;
	uint8_t data[DATA_SIZE];
};

struct data_response {
	uint64_t data_size;
	uint8_t data[DATA_SIZE];
};
// ----------------------

// Generate Symmetric key request, response structures
struct ecdh_request {
	uint8_t salt[SALT_SIZE];		// Salt value	
	uint8_t entity_id[ID_SIZE];	// Id of entity to share generated symmetric key
};
// ----------------------

// Sign document request, response structures
struct sign_request {
	uint32_t data_size;
	uint8_t data[DATA_SIZE];		// Data to be signed
};

struct sign_response {
	uint8_t signature[SIGNATURE_SIZE];	// Generated signature
	uint32_t signlen;			// Generated signature length
};
// ----------------------

// Verify document signature request, response structures
struct verify_request {
	uint8_t signature[SIGNATURE_SIZE];	// Data signature
	uint32_t signlen;			// Generated signature length
	uint8_t entity_id[ID_SIZE];		// ID of entity who signed the data
	uint32_t data_size;
	uint8_t data[DATA_SIZE];		// Data signed
};
// ----------------------

// Import public key request, response structures
struct pub_import {
	uint8_t entity_id[ID_SIZE];		// ID of entity
	uint8_t public_key[PUB_KEY_SIZE];	// Public key of the entity
	uint32_t cert_size;
};

// ----------------------

struct list_keys_response {
	uint8_t list[DATA_SIZE];	// List of keys
};
// ----------------------

// Main request structure with base parameters (op_code, status) and
// union structures, only one is used, depending on the operation
struct request {
	uint8_t op_code;	// Operation Code

	union {
		struct auth_request auth;
		struct admin_request admin;
		struct data_request data;
		struct ecdh_request gen_key;
		struct sign_request sign;
		struct verify_request verify;
		struct pub_import import_pub;
	};
};

// Main response structure with base parameters (op_code, status) and
// union structures, only one is used, depending on the operation
struct response {
	uint8_t op_code;	// Operation Code
	uint8_t status;		// Operation Status

	union {
		struct data_response data;
		struct sign_response sign;
		struct list_keys_response list;
	};
};

#endif 
