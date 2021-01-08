/*
 *  Copyright 2011-2016 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */


#include "pkcs11.h"
#include "../comms.h"

#define MAX_SESSIONS 1
#define MAX_SLOTS 1	// App só suport 1 token

#define P11_NUM_OPS 2
#define P11_OP_VERIFY 0
#define P11_OP_ENCRYPT 1

typedef struct p11_object_s {
	CK_OBJECT_CLASS oClass;
	CK_KEY_TYPE oType;
	CK_BBOOL oToken;
	CK_BYTE id[ID_SIZE];
	CK_BYTE id_size;
	CK_BYTE oValue[PUB_KEY_SIZE];
	CK_ULONG oValueLen;
} p11_object;

typedef struct p11_session_s {
	CK_SESSION_INFO_PTR session;
	CK_BYTE operation[P11_NUM_OPS];
	CK_BYTE op_code;

	p11_object obj; // Object - array of atrributes
} p11_session;

p11_session s;

// GLOBAL VARIABLES
CK_BBOOL init = CK_FALSE;
CK_BYTE session_count;
uint32_t pipe_fd;	// Pipe descriptor

struct request req;	// request structure
struct response resp;	// response structure


// p11_slot g_slots[MAX_SLOTS];

// std::vector<HSM*> devices_list; // the index represents the slotID (so the same device pointer may be in multiple indexes)
// std::vector<p11_session*> g_sessions;

CK_FUNCTION_LIST pkcs11_functions = 
{
	{2, 20},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent
};

/*
	Initializes Cryptoki
	Since we don't support multi-threading, the argument must be NULL

*/
CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	if (pInitArgs != NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (init)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	// add slot for HSM token
	// HSM * g_hsm = new HSM();
	// if (!g_hsm->init())
	//         return CKR_FUNCTION_FAILED;

	session_count = 0;
	init = CK_TRUE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	if (pReserved != NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	session_count = 0;

	init = CK_FALSE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &pkcs11_functions;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


// Operation 2: Set new authentication PIN
CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	CK_BYTE status;
	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;


	if (ulNewLen != (PIN_SIZE-2) || pNewPin == NULL)
		return CKR_PIN_INVALID;
	
	if(HSM_C_ChooseOpCode(hSession, 2) != CKR_OK)
		return CKF_LOGIN_REQUIRED;

	// send_to_connection(pipe_fd, pOldPin, ulOldLen);
	// receive_from_connection(pipe_fd, &status, sizeof(status));

	// if (!status)
	//         return CKR_PIN_INCORRECT;

	send_to_connection(pipe_fd, pNewPin, ulNewLen);

	if (!waitOK(pipe_fd))
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (session_count < MAX_SESSIONS)
		session_count++;
	else
		return CKR_SESSION_COUNT;

	// start session
	s.session = (CK_SESSION_INFO*)malloc(sizeof(CK_SESSION_INFO)); 
	s.session->slotID = slotID;
	s.session->flags = flags;
	s.session->ulDeviceError = 0;
	s.session->state = 0;

	s.operation[P11_OP_ENCRYPT] = 0;
	s.operation[P11_OP_VERIFY] = 0;
	s.op_code = 0;

	// s.obj = NULL_PTR; // Object

	*phSession = session_count-1;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (s.session == NULL_PTR)
		return CKR_SESSION_HANDLE_INVALID;

	// start session
	session_count--;
	free(s.session);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Operation 1: Authenticate
CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_BYTE ret, status;

	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (ulPinLen != (PIN_SIZE-2) || pPin == NULL)
		return CKR_PIN_INVALID;
	
	HSM_C_ChooseOpCode(hSession, 1);
	// if (ret != CKR_OK)
	//         return ret;

	send_to_connection(pipe_fd, pPin, ulPinLen);

	receive_from_connection(pipe_fd, &status, sizeof(CK_BYTE));
	if (status == 0)
		ret = CKR_FUNCTION_FAILED;
	else
		ret = CKR_OK;

	return ret;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(HSM_C_ChooseOpCode(hSession, 10) != CKR_OK)
		return CKF_LOGIN_REQUIRED;

	printf ("[CLIENT] Sending logout request\n");
	waitOK(pipe_fd);

	return CKR_OK;
}


// Can be used to create a new object on HSM
// Usefull for new certificate
// Operation 7: import public key certificate
CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	CK_LONG p = 0;
	CK_BYTE r;

	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pTemplate == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	for (p = 0; p < ulCount; p++)
	{
		if (pTemplate[p].type == CKA_CLASS)
			s.obj.oClass = *((CK_BYTE_PTR)pTemplate[p].pValue);
		else if (pTemplate[p].type == CKA_CERTIFICATE_TYPE || pTemplate[p].type == CKA_KEY_TYPE)
			s.obj.oType = *((CK_BYTE_PTR)pTemplate[p].pValue);
		else if (pTemplate[p].type == CKA_TOKEN)
			s.obj.oToken = *((CK_BYTE_PTR)pTemplate[p].pValue);
		else if (pTemplate[p].type == CKA_ID)
		{
			memcpy (s.obj.id, pTemplate[p].pValue, pTemplate[p].ulValueLen);
			s.obj.id_size = pTemplate[p].ulValueLen;
		}
		else if (pTemplate[p].type == CKA_VALUE && sizeof(s.obj.oValue) >= pTemplate[p].ulValueLen)
		{
			memcpy (s.obj.oValue, pTemplate[p].pValue, pTemplate[p].ulValueLen);
			s.obj.oValueLen = pTemplate[p].ulValueLen;
		}
	}
	*phObject = 1;
	r = CKR_OK;

	// if its to store on the server - its a certificate
	if (r == CKR_OK && s.obj.oType == CKC_X_509)
		return HSM_C_SaveObject(hSession, *phObject);

	return r;
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


// Operation 3: encrypt + authenticate
CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	s.op_code = 3;
	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism->mechanism != CKM_AES_CTR)
		return CKR_MECHANISM_INVALID;

	if (hKey != 1)
		return CKR_KEY_HANDLE_INVALID;

	// set operation flag
	s.operation[P11_OP_ENCRYPT] = 1;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (s.operation[P11_OP_ENCRYPT] != 1)
		return CKR_OPERATION_NOT_INITIALIZED;

	if(HSM_C_ChooseOpCode(hSession, s.op_code) != CKR_OK)
		return CKF_LOGIN_REQUIRED;
	// send data size
	send_to_connection(pipe_fd, &ulDataLen, sizeof(ulDataLen));
	if (!waitOK(pipe_fd))
	{
		s.operation[P11_OP_ENCRYPT] = 0;
		return CKR_DATA_INVALID;
	}

	// send data
	send_to_connection(pipe_fd, pData, ulDataLen);
	if (!waitOK(pipe_fd))
	{
		s.operation[P11_OP_ENCRYPT] = 0;
		return CKR_DATA_INVALID;
	}

	send_to_connection(pipe_fd, s.obj.id, s.obj.id_size); // send key ID
	if (!waitOK(pipe_fd))
	{
		s.operation[P11_OP_ENCRYPT] = 0;
		return CKR_FUNCTION_FAILED;
	}

	// Receives encrypt and authenticated data
	receive_from_connection(pipe_fd, pulEncryptedDataLen, sizeof(*pulEncryptedDataLen));
	sendOK(pipe_fd, (uint8_t *)"OK");
	receive_from_connection(pipe_fd, pEncryptedData, *pulEncryptedDataLen);
	sendOK(pipe_fd, (uint8_t *)"OK");

	s.operation[P11_OP_ENCRYPT] = 0;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


// Operation 4: decrypt + authenticate
CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	s.op_code = 4;
	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism->mechanism != CKM_AES_CTR)
		return CKR_MECHANISM_INVALID;

	if (hKey != 1)
		return CKR_KEY_HANDLE_INVALID;

	// set operation flag
	s.operation[P11_OP_ENCRYPT] = 1;

	return CKR_OK;
}


// Decryption is the same to encrypt with AES CTR mode
CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	return C_Encrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism->mechanism != CKM_ECDSA)
		return CKR_MECHANISM_INVALID;

	// Key object must be NULL_PTR (the HSM uses internal keys)
	if (hKey != NULL_PTR)
		return CKR_KEY_HANDLE_INVALID;

	// TODO
	// set operation code in structure
	return CKR_OK;
}


// Operation 5: sign data
CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_BYTE status;

	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(HSM_C_ChooseOpCode(hSession, 5) != CKR_OK)
		return CKF_LOGIN_REQUIRED;
	// send data size
	send_to_connection(pipe_fd, &ulDataLen, sizeof(ulDataLen));
	if(!waitOK(pipe_fd))
		return CKR_FUNCTION_FAILED;

	// send data
	send_to_connection(pipe_fd, pData, ulDataLen);

	receive_from_connection(pipe_fd, &status, sizeof(CK_BYTE));
	sendOK(pipe_fd, (uint8_t *)"OK");

	if (status != 0)
		return CKR_FUNCTION_FAILED;

	// Receives encrypt and authenticated data
	receive_from_connection(pipe_fd, pulSignatureLen, sizeof(pulSignatureLen));
	sendOK(pipe_fd, (uint8_t *)"OK");

	// Receives encrypt and authenticated data
	receive_from_connection(pipe_fd, pSignature, *pulSignatureLen);
	sendOK(pipe_fd, (uint8_t *)"OK");

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism->mechanism != CKM_ECDSA)
		return CKR_MECHANISM_INVALID;

	if (hKey != 1)
		return CKR_KEY_HANDLE_INVALID;

	// set operation flag
	s.operation[P11_OP_VERIFY] = 1;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_BYTE status;

	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// set operation flag
	if (s.operation[P11_OP_VERIFY] == 0)
		return CKF_LOGIN_REQUIRED;

	if(HSM_C_ChooseOpCode(hSession, 6) != CKR_OK)
		return CKF_LOGIN_REQUIRED;

	// send data size
	send_to_connection(pipe_fd, &ulDataLen, sizeof(ulDataLen));
	if(!waitOK(pipe_fd))
	{
		s.operation[P11_OP_VERIFY] = 0;
		return CKR_FUNCTION_FAILED;
	}

	// send data
	send_to_connection(pipe_fd, pData, ulDataLen);
	if(!waitOK(pipe_fd))
	{
		s.operation[P11_OP_VERIFY] = 0;
		return CKR_FUNCTION_FAILED;
	}

	// send signature size
	send_to_connection(pipe_fd, &ulSignatureLen, sizeof(ulSignatureLen));
	if(!waitOK(pipe_fd))
	{
		s.operation[P11_OP_VERIFY] = 0;
		return CKR_FUNCTION_FAILED;
	}

	// send signature
	send_to_connection(pipe_fd, pSignature, ulSignatureLen);
	if(!waitOK(pipe_fd))
	{
		s.operation[P11_OP_VERIFY] = 0;
		return CKR_FUNCTION_FAILED;
	}

	// send entity ID
	send_to_connection(pipe_fd, s.obj.id, s.obj.id_size);

	// Receives encrypt and authenticated data
	receive_from_connection(pipe_fd, &status, sizeof(uint8_t));
	sendOK(pipe_fd, (uint8_t *)"OK");

	s.operation[P11_OP_VERIFY] = 0;
	if (status > 0)
		return CKR_OK;
	else
		return CKR_FUNCTION_FAILED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


// Operation 8: Generate new key for sharing
CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_BYTE r, status;
	CK_ECDH1_DERIVE_PARAMS_PTR p;

	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL)
		return CKR_ARGUMENTS_BAD;

	if (pMechanism->mechanism != CKM_ECDH1_DERIVE)
		return CKR_MECHANISM_INVALID;

	p = pMechanism->pParameter;
	if (p == NULL || p->kdf != CKM_SHA256_KEY_DERIVATION)
		return CKR_MECHANISM_INVALID;

	// Shared key must be null
	if (p->ulSharedDataLen != 0 || p->pSharedData != NULL)
		return CKR_FUNCTION_FAILED;

	// Public key must be set
	if (p->ulPublicDataLen == 0 || p->pPublicData == NULL)
		return CKR_FUNCTION_FAILED;

	// key stays inside the HSM
	if (phKey != NULL)
		return CKR_OBJECT_HANDLE_INVALID;
	if (pTemplate != NULL)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	if(HSM_C_ChooseOpCode(hSession, 8) != CKR_OK)
		return CKF_LOGIN_REQUIRED;

	// send entity ID
	send_to_connection(pipe_fd, p->pPublicData , p->ulPublicDataLen);
	if(!waitOK(pipe_fd))
		return CKR_FUNCTION_FAILED;

	receive_from_connection(pipe_fd, &status, sizeof(CK_BYTE));
	sendOK(pipe_fd, (uint8_t *)"OK");

	if (status == 0)
		r = CKR_OK;
	else
		r = CKR_FUNCTION_FAILED;
	return r;
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, HSM_C_GetKeyList)(CK_SESSION_HANDLE phSession, CK_BYTE_PTR list)
{
	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get session

	if(HSM_C_ChooseOpCode(phSession, 9) != CKR_OK)
		return CKF_LOGIN_REQUIRED;

	receive_from_connection(pipe_fd, list, DATA_SIZE);
	sendOK(pipe_fd, (uint8_t *)"OK");

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, HSM_C_ChooseOpCode)(CK_SESSION_HANDLE phSession, CK_BYTE opcode)
{
	CK_BYTE r;
	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get session

	// Get greetings message
	// receive_from_connection(pipe_fd, greetings, sizeof(greetings));
	// printf ("%s", greetings);

	// Send op code and wait for confirmation
	// If error occurs, user must choose code:1 and authenticate with PIN
	send_to_connection(pipe_fd, &opcode, sizeof(CK_BYTE));
	if (!waitOK(pipe_fd))
	{
		r = CKF_LOGIN_REQUIRED;
	}
	else
		r = CKR_OK;

	if (r == CKF_LOGIN_REQUIRED && opcode != 1)
		printf ("NOT AUTHENTICATED\n");
	else if (r == CKR_CRYPTOKI_NOT_INITIALIZED)
		printf("Cryptoki not initialized\n");

	return r;
}

CK_DEFINE_FUNCTION(CK_RV, HSM_C_SaveObject)(CK_SESSION_HANDLE phSession, CK_OBJECT_HANDLE phObject)
{
	CK_BYTE r, status;
	if (!init)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (phObject != 1)
		return CKR_KEY_HANDLE_INVALID;

	if (s.obj.oClass != CKO_CERTIFICATE || s.obj.oType != CKC_X_509 || s.obj.oToken != CK_FALSE)
		return CKR_MECHANISM_INVALID;

	if(HSM_C_ChooseOpCode(phSession, 7) != CKR_OK)
		return CKF_LOGIN_REQUIRED;

	// send entity ID
	send_to_connection(pipe_fd, s.obj.id, s.obj.id_size);
	if(!waitOK(pipe_fd))
		return CKR_FUNCTION_FAILED;

	// Send certificate size
	send_to_connection(pipe_fd, &s.obj.oValueLen, sizeof(s.obj.oValueLen));
	if(!waitOK(pipe_fd))
		return CKR_FUNCTION_FAILED;
	// send certificate
	send_to_connection(pipe_fd, s.obj.oValue, s.obj.oValueLen);
	if(!waitOK(pipe_fd))
		return CKR_FUNCTION_FAILED;

	// Receives status
	receive_from_connection(pipe_fd, &status, sizeof(uint8_t));
	sendOK(pipe_fd, (uint8_t *)"OK");

	if (status != 0)
		r = CKR_OK;
	else
		r = CKR_FUNCTION_FAILED;
	return r;
}
