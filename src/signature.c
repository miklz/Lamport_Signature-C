
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "signature.h"

void GenerateKeys(key* prv, key* pub) {

  int tmp;
  for(int i = 0; i < BlockByteSize*256; i += 4) {
    tmp = rand();
    memcpy(&prv->zero[i], &tmp, sizeof(int));
    tmp = rand();
    memcpy(&prv->one[i], &tmp, sizeof(int));
  }

  SHA256_CTX ctx;

  for(int i = 0; i < BlockByteSize*256; i += BlockByteSize) {
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, &prv->zero[i], BlockByteSize);
    SHA256_Final(&pub->zero[i], &ctx);
  }

  for(int i = 0; i < BlockByteSize*256; i += BlockByteSize) {
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, &prv->one[i], BlockByteSize);
    SHA256_Final(&pub->one[i], &ctx);
  }
}

void Sign(key* prv, char* message, uint8_t *sign) {

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
        memcpy(&sign[index], &prv->one[index], BlockByteSize);
      } else {
        memcpy(&sign[index], &prv->zero[index], BlockByteSize);
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

int Verify(key* pub, char* message, uint8_t *sign) {

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
        if(!check_hash(&sign[index], &pub->one[index], BlockByteSize)) {
          printf("One wrong at block %d\n", i*8 + j);
          return 0;
        }
      } else {
        if(!check_hash(&sign[index], &pub->zero[index], BlockByteSize)) {
          printf("Zero wrong at block %d\n", i*8 + j);
          return 0;
        }
      }
    }
  }

  return 1;
}
