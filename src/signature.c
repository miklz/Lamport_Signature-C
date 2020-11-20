
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "signature.h"


void GenerateKeys(key* private, key* public) {

  uint8_t k = 0;
  srand(k);
  for(int i = 0; i < BlockByteSize*256; ++i) {
    private->zero[i] = rand();
    private->one[i] = rand();
  }

  SHA256_CTX ctx;

  for(int i = 0; i < BlockByteSize*256; i += BlockByteSize) {
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, &private->zero[i], BlockByteSize);
    SHA256_Final(&public->zero[i], &ctx);
  }

  for(int i = 0; i < BlockByteSize*256; i += BlockByteSize) {
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, &private->one[i], BlockByteSize);
    SHA256_Final(&public->one[i], &ctx);
  }
}

void Sign(key* private, char* message, uint8_t *sign) {

  unsigned char hash_message[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, message, strlen(message));
  SHA256_Final(hash_message, &ctx);

  uint16_t index;
  for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    for(int j = 0; j < 7; ++j) {
      index = (i*8 + j)*BlockByteSize;
      if(hash_message[i] & (1 << (7 - j))) {
        memcpy(&sign[index], &private->one[index], BlockByteSize);
      } else {
        memcpy(&sign[index], &private->zero[index], BlockByteSize);
      }
    }
  }
}

int check_hash(uint8_t *block, uint8_t *hash, int n) {

  uint8_t hash_block[SHA256_DIGEST_LENGTH];

  SHA256_CTX ctx;

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, block, n);
  SHA256_Final(hash_block, &ctx);

  if(memcmp(hash_block, hash, n))
    return 0;

  return 1;
}

int Verify(key* public, char* message, uint8_t *sign) {

  unsigned char hash_message[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, message, strlen(message));
  SHA256_Final(hash_message, &ctx);

  uint16_t index;
  for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    for(int j = 0; j < 7; ++j) {
      index = (i*8 + j)*BlockByteSize;
      if(hash_message[i] & (1 << (7 - j))) {
        if(!check_hash(&sign[index], &public->one[index], BlockByteSize)) {
          printf("One wrong at block %d\n", i*8 + j);
          return 0;
        }
      } else {
        if(!check_hash(&sign[index], &public->zero[index], BlockByteSize)) {
          printf("Zero wrong at block %d\n", i*8 + j);
          return 0;
        }
      }
    }
  }

  return 1;
}

