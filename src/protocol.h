#ifndef PROTOCOL_H
#define PROTOCOL_H

#define DATA_SIZE 65536		// 1 MB message size
#define HASH_SIZE 32		// 256 bit hash from SHA-256
#define SIGNATURE_SIZE 96	// 768 bit signature from curve P-384
#define ID_SIZE 10
#define PIN_SIZE 10
#define KEY_SIZE 16		// Symmetric key size - 256 + 128 bits
#define ECC_KEY_SIZE 48		// ECC 384 bit keys
#define PUB_KEY_SIZE 96		// ECC 768 bit public keys

// Authentication request, response structures
struct auth_request {
	char pin[PIN_SIZE];
};

struct auth_reponse {
};
// ----------------------

// Change authentication PIN request, response structures
struct admin_request {
	char pin[PIN_SIZE];
};

struct admin_reponse {
};
// ----------------------

// Data encryption/decryption request, response structures
struct data_request {
	short int data_size;
	char data[DATA_SIZE];
	char key_id[ID_SIZE];		// Id of symmetric key to encrypt data
};

struct data_response {
	short int data_size;
	char data[DATA_SIZE];
};
// ----------------------

// Generate Symmetric key request, response structures
struct gen_key_request {
	char entity_id[ID_SIZE];	// Id of entity to share generated symmetric key
	char key_id[ID_SIZE];		// Id of new symmetric key to generate
};

struct gen_key_response {
	short int msg_size;		// Size of message with encrypted key
	char msg[DATA_SIZE];		// Generated encrypted and signed symmetric key
	char key_id[ID_SIZE];		// Id of generated key
};
// ----------------------

// Save Symmetric key request, response structures
struct save_key_request {
	char msg[KEY_SIZE];		// Encrypted and signed key
	char entity_id[ID_SIZE];	// Id of entity who sent the symmetric key
	char key_id[ID_SIZE];		// Id of symmetric key to encrypt data
};

struct save_key_response {
};
// ----------------------

// Sign document request, response structures
struct sign_request {
	short int data_size;
	char data[DATA_SIZE];		// Data to be signed
};

struct sign_response {
	char signature[SIGNATURE_SIZE];	// Generated signature
};
// ----------------------

// Verify document signature request, response structures
struct verify_ds_request {
	char entity_id[ID_SIZE];	// ID of entity who signed the data
	short int data_size;
	char data[DATA_SIZE];		// Data signed
	char signature[SIGNATURE_SIZE]; // Generated signature
};

struct verify_ds_response {
};
// ----------------------

// Import public key request, response structures
struct import_pub_request {
	char entity_id[ID_SIZE];	// ID of entity
	char public_key[PUB_KEY_SIZE];	// Public key of the entity
};

struct import_pub_response {
};
// ----------------------

// Main request structure with base parameters (op_code, status) and
// union structures, only one is used, depending on the operation
struct request {
	char op_code;		// Operation Code
	char status;		// Operation Status

	union {
		struct auth_request auth;
		struct admin_request admin;
		struct data_request data;
		struct gen_key_request gen_key;
		struct save_key_request save_key;
		struct sign_request sign;
		struct verify_ds_request verify_ds;
		struct import_pub_request import_pub;
	};
};

// Main response structure with base parameters (op_code, status) and
// union structures, only one is used, depending on the operation
struct response {
	char op_code;		// Operation Code
	char status;		// Operation Status

	union {
		struct auth_reponse auth;
		struct admin_reponse admin;
		struct data_response data;
		struct gen_key_response gen_key;
		struct save_key_response save_key;
		struct sign_response sign;
		struct verify_ds_response verify_ds;
		struct import_pub_response import_pub;
	};
};

#endif 
