#include <stdint.h>
#include <string.h>
#include "inner.h"
#include "keccak_tiny.h"

int inner_keccak256_init(inner_keccak256_prng_ctx *sc) {
    if (!sc) return -1;
    
    memset(sc->buffer, 0, MAX_BUFFER_SIZE);
    memset(sc->state, 0, KECCAK256_OUTPUT);
    sc->buffer_len = 0;
    sc->counter = 0;
    sc->finalized = 0;
    return 0;
}

int inner_keccak256_inject(inner_keccak256_prng_ctx *sc, const uint8_t *in, size_t len) {
    if (!sc || !in) return -1;
    if (sc->finalized) return -2;

    // Check if we have enough space in buffer
    if (sc->buffer_len + len > MAX_BUFFER_SIZE) {
        return -3;  // Buffer would overflow
    }

    // Append new data to buffer
    memcpy(sc->buffer + sc->buffer_len, in, len);
    sc->buffer_len += len;
    return 0;
}

int inner_keccak256_flip(inner_keccak256_prng_ctx *sc) {
    if (!sc) return -1;
    if (sc->finalized) return -2;

    // Add SHAKE domain separation byte (0x1F)
    if (sc->buffer_len + 1 > MAX_BUFFER_SIZE) {
        return -3;
    }
    
    sc->buffer[sc->buffer_len++] = 0x1F;

    // Compute initial state using sha3_256
    int ret = sha3_256(sc->state, KECCAK256_OUTPUT, sc->buffer, sc->buffer_len);
    if (ret != 0) return ret;

    sc->finalized = 1;
    return 0;
}

int inner_keccak256_extract(inner_keccak256_prng_ctx *sc, uint8_t *out, size_t len) {
    if (!sc || !out) return -1;
    if (!sc->finalized) return -2;

    size_t offset = 0;
    uint8_t block[KECCAK256_OUTPUT + 8];  // State + counter
    uint8_t squeeze_out[KECCAK256_OUTPUT];
    int ret;

    while (offset < len) {
        // Prepare input block: state || counter
        memcpy(block, sc->state, KECCAK256_OUTPUT);
        // Add counter in big-endian format
        for (int i = 0; i < 8; i++) {
            block[KECCAK256_OUTPUT + i] = (sc->counter >> (56 - i * 8)) & 0xFF;
        }

        // Generate next block
        ret = sha3_256(squeeze_out, KECCAK256_OUTPUT, block, KECCAK256_OUTPUT + 8);
        if (ret != 0) return ret;

        // Copy output
        size_t to_copy = len - offset;
        if (to_copy > KECCAK256_OUTPUT) {
            to_copy = KECCAK256_OUTPUT;
        }
        memcpy(out + offset, squeeze_out, to_copy);

        offset += to_copy;
        sc->counter++;
    }
    return 0;
}