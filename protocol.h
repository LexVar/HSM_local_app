#ifndef PROTOCOL_H
#define PROTOCOL_H

#define MSG_SIZE 65536
#define SIGNATURE_SIZE 32
#define ID_SIZE 10
#define KEY_SIZE 16
#define PUBKEY_SIZE 16

struct base_request {
	char type;
	char session_id[32];
};

struct base_response {
	char type;
	char status;
	char session_id[32];
};

struct auth_request {
	int pin;
};

struct auth_reponse {
};

struct admin_request {
	int pin;
};

struct admin_reponse {
};

struct msg_request {
	short int msg_size;
	char msg[MSG_SIZE];
	char key_id[ID_SIZE];
};

struct msg_response {
	short int msg_size;
	char msg[MSG_SIZE];
};

struct save_key_request {
	char msg[KEY_SIZE];
	char user_id[ID_SIZE];
	char key_id[ID_SIZE];
};

struct save_key_response {
};

struct share_key_request {
	char user_id[ID_SIZE];
	char key_id[ID_SIZE];
};

struct share_key_response {
	char user_id[ID_SIZE];
	char msg[MSG_SIZE];
	char key_id[ID_SIZE];
};

struct sign_request {
	short int msg_size;
	char msg[MSG_SIZE];
};

struct sign_response {
	short int msg_size;
	char msg[MSG_SIZE];
	char signature[SIGNATURE_SIZE];
};

struct verify_signature_request {
	char user_id[ID_SIZE];
	short int msg_size;
	char msg[MSG_SIZE];
	char signature[SIGNATURE_SIZE];
};

struct verify_signature_response {
};

struct import_pub_request {
	char user_id[ID_SIZE];
	char public_key[PUBKEY_SIZE];
};

struct import_pub_response {
};

struct composed_request {
	struct base_request request;

	union {
		struct auth_request auth_req;
		struct admin_request admin_req;
		struct msg_request msg_req;
	};
};

struct composed_response {
	struct base_response response;

	union {
		struct auth_reponse auth_res;
		struct admin_reponse admin_res;
		struct msg_response msg_res;
	};
};

#endif 
