#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "inner.h"

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void test_basic_functionality() {
    printf("Test: Basic Functionality\n");
    
    inner_keccak256_prng_ctx ctx;
    uint8_t input[] = "test input";
    uint8_t output1[32];
    uint8_t output2[32];
    int ret;
    
    // Test 1: Same input should generate same output
    ret = inner_keccak256_prng_init(&ctx);
    assert(ret == 0);
    ret = inner_keccak256_prng_absorb(&ctx, input, strlen((char*)input));
    assert(ret == 0);
    ret = inner_keccak256_prng_finalize(&ctx);
    assert(ret == 0);
    ret = inner_keccak256_prng_squeeze(output1, 32, &ctx);
    assert(ret == 0);
    
    inner_keccak256_prng_ctx ctx2;
    ret = inner_keccak256_prng_init(&ctx2);
    assert(ret == 0);
    ret = inner_keccak256_prng_absorb(&ctx2, input, strlen((char*)input));
    assert(ret == 0);
    ret = inner_keccak256_prng_finalize(&ctx2);
    assert(ret == 0);
    ret = inner_keccak256_prng_squeeze(output2, 32, &ctx2);
    assert(ret == 0);
    
    assert(memcmp(output1, output2, 32) == 0);
    printf("PASSED: Same input generates same output\n");
}

void test_different_lengths() {
    printf("\nTest: Different Output Lengths\n");
    
    inner_keccak256_prng_ctx ctx;
    uint8_t input[] = "test input";
    uint8_t output32[32];
    uint8_t output64[64];
    int ret;
    
    ret = inner_keccak256_prng_init(&ctx);
    assert(ret == 0);
    ret = inner_keccak256_prng_absorb(&ctx, input, strlen((char*)input));
    assert(ret == 0);
    ret = inner_keccak256_prng_finalize(&ctx);
    assert(ret == 0);
    ret = inner_keccak256_prng_squeeze(output32, 32, &ctx);
    assert(ret == 0);
    ret = inner_keccak256_prng_squeeze(output64, 64, &ctx);
    assert(ret == 0);
    
    assert(memcmp(output32, output64, 32) != 0);
    printf("PASSED: Different length outputs are unique\n");
}

void test_incremental_absorption() {
    printf("\nTest: Incremental Absorption\n");
    
    inner_keccak256_prng_ctx ctx1, ctx2;
    uint8_t input1[] = "test";
    uint8_t input2[] = "input";
    uint8_t output1[32];
    uint8_t output2[32];
    int ret;
    
    // Absorb in one go
    ret = inner_keccak256_prng_init(&ctx1);
    assert(ret == 0);
    ret = inner_keccak256_prng_absorb(&ctx1, (uint8_t*)"testinput", 9);
    assert(ret == 0);
    ret = inner_keccak256_prng_finalize(&ctx1);
    assert(ret == 0);
    ret = inner_keccak256_prng_squeeze(output1, 32, &ctx1);
    assert(ret == 0);
    
    // Absorb incrementally
    ret = inner_keccak256_prng_init(&ctx2);
    assert(ret == 0);
    ret = inner_keccak256_prng_absorb(&ctx2, input1, 4);
    assert(ret == 0);
    ret = inner_keccak256_prng_absorb(&ctx2, input2, 5);
    assert(ret == 0);
    ret = inner_keccak256_prng_finalize(&ctx2);
    assert(ret == 0);
    ret = inner_keccak256_prng_squeeze(output2, 32, &ctx2);
    assert(ret == 0);
    
    assert(memcmp(output1, output2, 32) == 0);
    printf("PASSED: Incremental absorption matches single absorption\n");
}

void test_error_conditions() {
    printf("\nTest: Error Conditions\n");
    
    inner_keccak256_prng_ctx ctx;
    uint8_t output[32];
    uint8_t input[] = "test";
    int ret;
    
    // Test NULL context
    ret = inner_keccak256_prng_init(NULL);
    assert(ret != 0);
    
    // Test absorb after finalize
    ret = inner_keccak256_prng_init(&ctx);
    assert(ret == 0);
    ret = inner_keccak256_prng_finalize(&ctx);
    assert(ret == 0);
    ret = inner_keccak256_prng_absorb(&ctx, input, 4);
    assert(ret != 0);
    
    // Test squeeze before finalize
    ret = inner_keccak256_prng_init(&ctx);
    assert(ret == 0);
    ret = inner_keccak256_prng_squeeze(output, 32, &ctx);
    assert(ret != 0);
    
    printf("PASSED: Error conditions properly handled\n");
}

void test_buffer_limits() {
    printf("\nTest: Buffer Limits\n");
    
    inner_keccak256_prng_ctx ctx;
    uint8_t large_input[MAX_BUFFER_SIZE + 1];
    int ret;
    
    memset(large_input, 'A', MAX_BUFFER_SIZE + 1);
    
    ret = inner_keccak256_prng_init(&ctx);
    assert(ret == 0);
    
    // This should return error
    ret = inner_keccak256_prng_absorb(&ctx, large_input, MAX_BUFFER_SIZE + 1);
    assert(ret != 0);
    
    printf("PASSED: Buffer overflow protection works\n");
}

int main() {
    printf("Running Keccak256 PRNG Tests\n");
    printf("=============================\n\n");
    
    test_basic_functionality();
    test_different_lengths();
    test_incremental_absorption();
    test_error_conditions();
    test_buffer_limits();
    
    printf("\nAll tests passed successfully!\n");
    return 0;
}