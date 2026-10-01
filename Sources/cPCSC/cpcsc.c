#include "cpcsc.h"

#if defined(__linux__)

#include <string.h>
#include <winscard.h>

int32_t cpcsc_context_create(uintptr_t *out_context) {
	SCARDCONTEXT ctx = 0;
	LONG rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
	if (rc == SCARD_S_SUCCESS) {
		*out_context = (uintptr_t)ctx;
	}
	return (int32_t)rc;
}

int32_t cpcsc_context_release(uintptr_t context) {
	return (int32_t)SCardReleaseContext((SCARDCONTEXT)context);
}

int32_t cpcsc_list_readers(uintptr_t context, char *buffer, uint32_t *buffer_size_inout) {
	DWORD size = (DWORD)*buffer_size_inout;
	LONG rc = SCardListReaders((SCARDCONTEXT)context, NULL, buffer, &size);
	*buffer_size_inout = (uint32_t)size;
	return (int32_t)rc;
}

int32_t cpcsc_connect(uintptr_t context, const char *reader_name, uintptr_t *out_card, uint32_t *out_protocol) {
	SCARDHANDLE card = 0;
	DWORD protocol = 0;
	LONG rc = SCardConnect((SCARDCONTEXT)context, reader_name, SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card, &protocol);
	if (rc == SCARD_S_SUCCESS) {
		*out_card = (uintptr_t)card;
		*out_protocol = (uint32_t)protocol;
	}
	return (int32_t)rc;
}

int32_t cpcsc_transmit(uintptr_t card, const uint8_t *apdu, uint32_t apdu_size, uint8_t *response, uint32_t *response_size_inout, uint32_t protocol) {
	DWORD response_size = (DWORD)*response_size_inout;
	const SCARD_IO_REQUEST *pio = (protocol == SCARD_PROTOCOL_T1) ? &g_rgSCardT1Pci : &g_rgSCardT0Pci;
	LONG rc = SCardTransmit((SCARDHANDLE)card, pio, apdu, (DWORD)apdu_size, NULL, response, &response_size);
	*response_size_inout = (uint32_t)response_size;
	return (int32_t)rc;
}

int32_t cpcsc_status(uintptr_t card) {
	DWORD state = 0;
	DWORD protocol = 0;
	char reader_name[256] = {0};
	DWORD reader_name_size = sizeof(reader_name) - 1;
	LONG rc = SCardStatus((SCARDHANDLE)card, reader_name, &reader_name_size, &state, &protocol, NULL, NULL);
	return (int32_t)rc;
}

int32_t cpcsc_disconnect(uintptr_t card) {
	return (int32_t)SCardDisconnect((SCARDHANDLE)card, SCARD_LEAVE_CARD);
}

#else

/* PC/SC support is Linux-only; these stubs keep the target buildable
   on other platforms (the Swift layer is also gated to Linux). */

#define CPCSC_UNSUPPORTED (-1)

int32_t cpcsc_context_create(uintptr_t *out_context) {
	(void)out_context;
	return CPCSC_UNSUPPORTED;
}

int32_t cpcsc_context_release(uintptr_t context) {
	(void)context;
	return CPCSC_UNSUPPORTED;
}

int32_t cpcsc_list_readers(uintptr_t context, char *buffer, uint32_t *buffer_size_inout) {
	(void)context;
	(void)buffer;
	(void)buffer_size_inout;
	return CPCSC_UNSUPPORTED;
}

int32_t cpcsc_connect(uintptr_t context, const char *reader_name, uintptr_t *out_card, uint32_t *out_protocol) {
	(void)context;
	(void)reader_name;
	(void)out_card;
	(void)out_protocol;
	return CPCSC_UNSUPPORTED;
}

int32_t cpcsc_transmit(uintptr_t card, const uint8_t *apdu, uint32_t apdu_size, uint8_t *response, uint32_t *response_size_inout, uint32_t protocol) {
	(void)card;
	(void)apdu;
	(void)apdu_size;
	(void)response;
	(void)response_size_inout;
	(void)protocol;
	return CPCSC_UNSUPPORTED;
}

int32_t cpcsc_status(uintptr_t card) {
	(void)card;
	return CPCSC_UNSUPPORTED;
}

int32_t cpcsc_disconnect(uintptr_t card) {
	(void)card;
	return CPCSC_UNSUPPORTED;
}

#endif
