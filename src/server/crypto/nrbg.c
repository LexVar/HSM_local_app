#include "nrbg.h"

//------------------------------------------------------------------------------
uint8_t release_drbg_service(uint8_t drbg_handle)
{
	return MSS_SYS_nrbg_uninstantiate(drbg_handle);
}

//------------------------------------------------------------------------------
uint8_t reserve_drbg_service(uint8_t * drbg_handle)
{
	const uint8_t personalization_str[4] = {0x12, 0x34, 0x56, 0x78};

	return MSS_SYS_nrbg_instantiate(personalization_str, 0, &drbg_handle);
}

//------------------------------------------------------------------------------
uint8_t reset_drbg_service()
{
	return MSS_SYS_nrbg_reset();
}

//------------------------------------------------------------------------------
uint8_t reseed_drbg_service(uint8_t drbg_handle)
{
	const uint8_t additional_input[4] = {0x12, 0x34, 0x56, 0x78};
	//uint8_t input_length;

	return MSS_SYS_nrbg_reseed( additional_input, sizeof(additional_input), drbg_handle);
}

//------------------------------------------------------------------------------
//Generate random bit function
#define MAX_NB_OF_RANDOM_BYTES      128
uint8_t generate_random_bits(uint8_t drbg_handle, uint8_t nb_of_bytes, uint8_t * random_bytes)
{
	uint8_t random_bytes[MAX_NB_OF_RANDOM_BYTES];
	uint8_t status;
	uint32_t inc;

	if((nb_of_bytes > 1) && (nb_of_bytes <= MAX_NB_OF_RANDOM_BYTES))
		// p_requested_data, p_additional_input, requested_length, additional_input_length, pr_req, drbg_handle
		status = MSS_SYS_nrbg_generate(random_bytes,0, nb_of_bytes, 0, 0, drbg_handle);
	else
		status = MSS_SYS_NRBG_MAX_LENGTH_EXCEEDED;
	return status;
}
