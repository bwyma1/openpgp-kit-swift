#ifndef CPCSC_H
#define CPCSC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Minimal PC/SC (libpcsclite) wrapper used by openpgp-kit-swift on Linux.
///
/// Every function returns 0 on success (`SCARD_S_SUCCESS`); any other value is
/// the raw PC/SC error code (`LONG`, signed 32-bit). The caller maps error
/// codes to domain errors.
///
/// Note: on 64-bit Linux `SCARDCONTEXT`/`SCARDHANDLE` are `unsigned long`, so
/// they are exposed as `uintptr_t` boxing.

/// Establish the process-wide PC/SC resource-manager context.
int32_t cpcsc_context_create(uintptr_t *out_context);

/// Release the resource-manager context.
int32_t cpcsc_context_release(uintptr_t context);

/// List available readers as a double-NUL-terminated multi-string.
/// Pass `buffer == NULL` with *buffer_size = 0 to query the required size.
int32_t cpcsc_list_readers(uintptr_t context, char *buffer, uint32_t *buffer_size_inout);

/// Connect to the given reader (shared, both T=0 and T=1 offered).
/// On success fills *out_card and *out_protocol with the negotiated protocol.
int32_t cpcsc_connect(uintptr_t context, const char *reader_name, uintptr_t *out_card, uint32_t *out_protocol);

/// Transmit an APDU. On input *response_size_inout holds the response buffer
/// capacity; on output it holds the number of response bytes received
/// (including status words).
int32_t cpcsc_transmit(uintptr_t card, const uint8_t *apdu, uint32_t apdu_size, uint8_t *response, uint32_t *response_size_inout, uint32_t protocol);

/// Query whether the card is present and usable. Returns SCARD_S_SUCCESS when ok.
int32_t cpcsc_status(uintptr_t card);

/// Disconnect, leaving the card in place.
int32_t cpcsc_disconnect(uintptr_t card);

#ifdef __cplusplus
}
#endif

#endif
