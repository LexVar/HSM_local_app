#include "client.h"

int main(void)
{
	CK_RV r;
	CK_MECHANISM sign_mechanism;
	CK_ECDH1_DERIVE_PARAMS ecdh;
	CK_OBJECT_CLASS class;
	CK_CERTIFICATE_TYPE certType;
	CK_BBOOL false;

	// Redirects SIGINT (CTRL-c) to cleanup()
	signal(SIGINT, cleanup);

	if (C_Initialize(NULL) != CKR_OK)
	{
		printf("C_Initialize - error ocurred\n");
		exit(-1);
	}

	while (1) {

		printf ("Press ENTER to continue...\n");
		flush_stdin();

		r = HSM_C_ChooseOpCode(0, &req.op_code);
		if (r == CKF_LOGIN_REQUIRED && req.op_code != 1)
		{
			printf ("NOT AUTHENTICATED\n");
			continue;
		}
		else if (r == CKR_CRYPTOKI_NOT_INITIALIZED)
		{
			printf("Cryptoki not initialized\n");
			continue;
		}

		// ------------------------------
		switch (req.op_code)
		{
			case 1: // Authentication request
				printf("PIN: ");

				if (fgets((char *)req.auth.pin, PIN_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting PIN, try again..\n");
					return 0;
				}
				flush_stdin();

				if (C_Login(0, 0, req.auth.pin, PIN_SIZE) == CKR_OK)
					printf("[CLIENT] Authentication SUCCESS\n");
				else
					printf("[CLIENT] Authentication failed\n");

				break;
			case 2:	// Change authentication PIN
				printf("Old PIN: ");
				if (fgets((char *)req.auth.pin, PIN_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting PIN, try again..\n");
					continue;
				}
				flush_stdin();

				printf("New PIN: ");
				if (fgets((char *)req.admin.pin, PIN_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting PIN, try again..\n");
					continue;
				}
				flush_stdin();

				if (C_SetPIN(0, req.auth.pin, PIN_SIZE, req.admin.pin, PIN_SIZE) == CKR_OK)
					printf("[CLIENT] PIN succesfully set\n");
				else
					printf("[CLIENT] Operation failed \n");
				break;
			case 3: // Encrypt and authenticate data
				encrypt_authenticate((uint8_t *)"data.enc");
				break;
			case 4: // Decrypt and authenticate data
				encrypt_authenticate((uint8_t *)"data.txt");
				break;
			case 5:	// Sign message
				printf("Data filename: ");
				if ((req.sign.data_size = get_attribute_from_file(req.sign.data)) == 0)
				{
					printf("Some error\n");
					req.sign.data[0] = 0;
				}

				sign_mechanism.mechanism = CKM_ECDSA;
				sign_mechanism.pParameter = NULL_PTR;
				sign_mechanism.ulParameterLen = 0;
				// sign_mechanism = { CKM_ECDSA, NULL_PTR, 0 };
				r = C_SignInit(0, &sign_mechanism, NULL_PTR);
				if (r != CKR_OK)
				{
					printf("C_SignInit Failed: %ld\n", r);
					continue;
				}
				r = C_Sign(0, req.sign.data, req.sign.data_size, resp.sign.signature, NULL);
				if (r != CKR_OK)
				{
					printf("C_Sign Failed: %ld\n", r);
					continue;
				}
				printf ("[CLIENT] Signature: (\"signature.txt\"):\n%s\n", resp.sign.signature);
				write_to_file ((uint8_t *)"signature.txt", resp.sign.signature, SIGNATURE_SIZE);
				break;
			case 6:	// Sign message
				printf("Data filename: ");
				if ((req.verify.data_size = get_attribute_from_file(req.verify.data)) == 0)
				{
					printf ("Some error\n");
					req.verify.data[0] = 0;
				}

				printf("Signature filename: ");
				if (get_attribute_from_file(req.verify.signature) == 0)
					printf ("Some error\n");

				printf("Entity's ID: ");
				if (fgets((char *)req.verify.entity_id, ID_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting ID, try again..\n");
					req.verify.entity_id[0] = 0;
				}

				sign_mechanism.mechanism = CKM_ECDSA;
				sign_mechanism.pParameter = NULL_PTR;
				sign_mechanism.ulParameterLen = 0;
				r = C_VerifyInit(0, &sign_mechanism, NULL_PTR);
				if (r != CKR_OK)
				{
					printf("C_VerifyInit Failed: %ld\n", r);
					continue;
				}
				r = C_Verify(0, req.verify.data, req.verify.data_size, req.verify.signature, SIGNATURE_SIZE);
				if (r != CKR_OK)
				{
					printf("C_Verify Failed: %lx\n", r);
					printf ("[CLIENT] Signature failed verification\n");
					continue;
				}
				else
					printf ("[CLIENT] Signature successfully verified\n");
				break;
			case 7:	// Import public key

				printf("Entity's ID: ");
				if (fgets((char *)req.import_pub.entity_id, ID_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting ID, try again..\n");
					req.verify.entity_id[0] = 0;
				}

				printf("Public key filename: ");
				if ((req.import_pub.cert_size = get_attribute_from_file(req.import_pub.public_key)) == 0)
					printf ("Some error\n");

				class = CKO_CERTIFICATE;
				certType = CKC_X_509;
				false = CK_FALSE;
				CK_ATTRIBUTE template[] = {
					{CKA_CLASS, &class, sizeof(class)},
					{CKA_CERTIFICATE_TYPE, &certType, sizeof(certType)},
					{CKA_TOKEN, &false, sizeof(false)},
						// The id must be set
						// Must be before the certificate data CKA_VALUE
					{CKA_ID, req.import_pub.entity_id, sizeof(req.import_pub.entity_id)},
					{CKA_VALUE, req.import_pub.public_key, req.import_pub.cert_size} };

				// The handle is null since the certificate will not be saved locally, only HSM
				r = C_CreateObject (0, template, 5, NULL);

				if (r != CKR_OK)
					printf ("[CLIENT] Error saving certificate\n");
				else
					printf ("[CLIENT] Certificate successfully saved\n");
				// import_pubkey_operation();
				break;
			case 8: // New communications key
				printf("Entity's ID (to share key with): ");
				if (fgets((char *)req.gen_key.entity_id, ID_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting ID, try again..\n");
					req.gen_key.entity_id[0] = 0;
				}
				// Set ECDH mechanisms and sha256 key derivation
				ecdh.kdf = CKM_SHA256_KEY_DERIVATION;
				ecdh.ulSharedDataLen = 0;
				ecdh.pSharedData = NULL;
				ecdh.pPublicData = req.gen_key.entity_id;
				ecdh.ulPublicDataLen = ID_SIZE;
				CK_MECHANISM mechanism;
				mechanism.pParameter = (CK_ECDH1_DERIVE_PARAMS_PTR)&ecdh;
				mechanism.ulParameterLen = sizeof(CK_ECDH1_DERIVE_PARAMS);
				mechanism.mechanism = CKM_ECDH1_DERIVE; 

				r = C_DeriveKey(0, &mechanism, 0, NULL, 0, NULL);
				if (r != CKR_OK)
				{
					printf("C_Derive Failed: %lx\n", r);
					printf ("[CLIENT] Some error ocurred deriving shared secret\n");
				}
				else
					printf ("[CLIENT] Key successfully generated and saved with key_id: %s\n", req.gen_key.entity_id);
				break;
			case 9: // Get available symmetric key list
				if (HSM_C_GetKeyList(0, resp.list.list) == CKR_OK)
					printf("List of keys:\n%s\n", resp.list.list);
				else
					printf("Function error \n");
				break;
			case 10: // Logout request
				printf ("[CLIENT] Sending logout request\n");
				waitOK(pipe_fd);
				break;
			case 0:
				printf("[CLIENT] Stopping client..\n");
				exit(0);
				break;
			default:
				waitOK(pipe_fd);
				printf("\n[CLIENT] %d. Is not a valid operation\n", req.op_code);
		}
	}
	return 0;
}

// Operation 3: encrypt + authenticate
// Operation 4: decrypt + authenticate
void encrypt_authenticate(uint8_t * file)
{
	printf("Data filename: ");
	if ((req.data.data_size = get_attribute_from_file(req.data.data)) == 0)
	{
		printf ("Some error\n");
	}

	// send data size
	send_to_connection(pipe_fd, &req.data.data_size, sizeof(req.data.data_size));
	if (!waitOK(pipe_fd))
		return;

	// send data
	send_to_connection(pipe_fd, req.data.data, req.data.data_size);
	if (!waitOK(pipe_fd))
		return;

	printf("Key ID to use to encrypt/decrypt data: ");
	if (fgets((char *)req.data.key_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID\n");
		req.data.key_id[0] = 0; // marks it's invalid
	}

	send_to_connection(pipe_fd, req.data.key_id, ID_SIZE); // send key ID
	if (!waitOK(pipe_fd))
		return;

	// Receives encrypt and authenticated data
	receive_from_connection(pipe_fd, &resp.data.data_size, sizeof(req.data.data_size));
	sendOK(pipe_fd, (uint8_t *)"OK");
	receive_from_connection(pipe_fd, resp.data.data, resp.data.data_size);
	sendOK(pipe_fd, (uint8_t *)"OK");

	if (resp.data.data_size <= 0)
		printf ("Some error ocurred data\n");
	else
	{
		// If success, data in resp.data.data
		resp.data.data[resp.data.data_size] = 0;
		printf ("[CLIENT] Data (\"%s\"):\n%s\n", file, resp.data.data);
		write_to_file ((uint8_t *)file, resp.data.data, resp.data.data_size);
	}
}

uint32_t get_attribute_from_file (uint8_t * attribute)
{
	uint8_t filename[ID_SIZE];

	if (fgets((char *)filename, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting filename, try again..\n");
		return 0;
	}
	filename[strlen((char *)filename)-1] = 0; // Remove newline from filename

	// get data and size from file
	return read_from_file (filename, attribute);
}

void cleanup()
{
	printf ("\n[CLIENT] Cleaning up...\n");
	/* place all cleanup operations here */
	close(pipe_fd);
	exit (0);
}
