#ifndef TAPSMITH_H
#define TAPSMITH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TAPSMITH_ABI_VERSION 1u
#define TAPSMITH_GALLAGHER_CREDENTIAL_LEN 8u

typedef int32_t tapsmith_status_t;

#define TAPSMITH_STATUS_OK 0
#define TAPSMITH_STATUS_NULL_POINTER 1
#define TAPSMITH_STATUS_INVALID_LENGTH 2
#define TAPSMITH_STATUS_INVALID_CREDENTIAL 3

typedef struct tapsmith_gallagher_credential {
    uint8_t region_code;
    uint16_t facility_code;
    uint32_t card_number;
    uint8_t issue_level;
} tapsmith_gallagher_credential_t;

uint32_t tapsmith_abi_version(void);

size_t tapsmith_gallagher_credential_len(void);

tapsmith_status_t tapsmith_gallagher_credential_decode(
    const uint8_t *data,
    size_t data_len,
    tapsmith_gallagher_credential_t *out_credential
);

tapsmith_status_t tapsmith_gallagher_credential_encode(
    const tapsmith_gallagher_credential_t *credential,
    uint8_t *out_data,
    size_t out_data_len
);

#ifdef __cplusplus
}
#endif

#endif
