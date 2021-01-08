#include "client.h"

int main(void)
{
	CK_RV r;
	CK_MECHANISM mechanism;
	CK_ECDH1_DERIVE_PARAMS ecdh;
	CK_OBJECT_CLASS class;
	CK_OBJECT_HANDLE obj;
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

		display_greeting();

		// Input op code from stdin
		scanf("%hhd", &req.op_code);
		flush_stdin();

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
			case 4: // Decrypt and authenticate data

				printf("Data filename: ");
				if ((req.data.data_size = get_attribute_from_file(req.data.data)) == 0)
				{
					printf ("Some error\n");
				}

				printf("Key ID to use to encrypt/decrypt data: ");
				if (fgets((char *)req.data.key_id, ID_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting ID\n");
					req.data.key_id[0] = 0; // marks it's invalid
				}

				class = CKO_SECRET_KEY;
				certType = CKC_X_509;
				false = CK_FALSE;
				CK_ATTRIBUTE template1[] = {
					{CKA_CLASS, &class, sizeof(class)},
					{CKA_CERTIFICATE_TYPE, &certType, sizeof(certType)},
					{CKA_TOKEN, &false, sizeof(false)},
					{CKA_ID, req.data.key_id, ID_SIZE} };

				r = C_CreateObject (0, template1, 4, &obj);

				mechanism.mechanism = CKM_AES_CTR;
				mechanism.pParameter = NULL_PTR;
				mechanism.ulParameterLen = 0;

				r = C_EncryptInit(0, &mechanism, obj);
				if (r != CKR_OK)
				{
					printf("C_EncryptInit Failed: %ld\n", r);
					continue;
				}
				r = C_Encrypt(0, req.data.data, req.data.data_size, resp.data.data, (CK_ULONG_PTR)&resp.data.data_size);
				if (r != CKR_OK)
				{
					printf("C_Encrypt Failed: %ld\n", r);
					continue;
				}

				if (resp.data.data_size <= 0 || r != CKR_OK)
					printf ("Some error ocurred data\n");
				else if (req.op_code == 3)
				{
					// If success, data in resp.data.data
					resp.data.data[resp.data.data_size] = 0;
					printf ("[CLIENT] Data (\"data.enc\"):\n%s\n", resp.data.data);
					write_to_file ((uint8_t *)"data.enc", resp.data.data, resp.data.data_size);
				}
				else if (req.op_code == 4)
				{
					// If success, data in resp.data.data
					resp.data.data[resp.data.data_size] = 0;
					printf ("[CLIENT] Data (\"data.txt\"):\n%s\n", resp.data.data);
					write_to_file ((uint8_t *)"data.txt", resp.data.data, resp.data.data_size);
				}
				// if (req.op_code == 3)
				//         encrypt_authenticate((uint8_t *)"data.enc");
				// else // 4
				//         encrypt_authenticate((uint8_t *)"data.txt");
				break;
			case 5:	// Sign message
				printf("Data filename: ");
				if ((req.sign.data_size = get_attribute_from_file(req.sign.data)) == 0)
				{
					printf("Some error\n");
					req.sign.data[0] = 0;
				}

				mechanism.mechanism = CKM_ECDSA;
				mechanism.pParameter = NULL_PTR;
				mechanism.ulParameterLen = 0;
				// mechanism = { CKM_ECDSA, NULL_PTR, 0 };
				r = C_SignInit(0, &mechanism, NULL_PTR);
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

				class = CKO_DATA;
				false = CK_FALSE;
				CK_ATTRIBUTE template2[] = {
					{CKA_CLASS, &class, sizeof(class)},
					{CKA_TOKEN, &false, sizeof(false)},
					{CKA_ID, req.verify.entity_id, ID_SIZE} };

				r = C_CreateObject (0, template2, 3, &obj);

				mechanism.mechanism = CKM_ECDSA;
				mechanism.pParameter = NULL_PTR;
				mechanism.ulParameterLen = 0;
				r = C_VerifyInit(0, &mechanism, obj);
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
				r = C_CreateObject (0, template, 5, &obj);

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
				C_Logout(0);
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

void display_greeting ()
{
	uint8_t greeting [] ="\n--CLIENT OPERATIONS--\n\
1. Authentication\n\
2. Change PIN\n\
3. Encrypt message\n\
4. Decrypt message\n\
5. Sign message\n\
6. Verify signature\n\
7. Import public key\n\
8. New comms key\n\
9. List comm keys\n\
10. Logout\n\
0. Quit\n\
--------------------\n\n\
Operation: ";
	printf ("%s", greeting);
}

void cleanup()
{
	printf ("\n[CLIENT] Cleaning up...\n");
	/* place all cleanup operations here */
	close(pipe_fd);
	exit (0);
}
