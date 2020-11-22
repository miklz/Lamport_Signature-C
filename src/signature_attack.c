
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "signature.h"
#include "signature_attack.h"

static unsigned long long int nounce = 0;

typedef struct ThreadData {
  uint8_t threadID;
  key *public;
  key *false_key;
  char *message;
  unsigned long long int start;
} threadData;

void copy_signature(key* pub, signatures *clues, key *false_key) {

  printf("Copying Signatures...\n");

  int one, zero;
  for(int i = 0; i < 256; ++i) {
    one = 0;
    zero = 0;

    for(int j = 0; j < clues->n; ++j){
      if(check_hash(&clues->sign[j][i*BlockByteSize], &pub->one[i*BlockByteSize], BlockByteSize)) {
        memcpy(&false_key->one[i*BlockByteSize], &clues->sign[j][i*BlockByteSize], BlockByteSize);
        one = 1;
      } else {
        memcpy(&false_key->zero[i*BlockByteSize], &clues->sign[j][i*BlockByteSize], BlockByteSize);
        zero = 1;
      }

      if(one && zero) break;
    }
  }

  printf("Done\n");
}

void *forge_signature(void *args) {

  threadData *thData = (threadData *) args;

  uint8_t id = thData->threadID;
  key *public = thData->public;
  key *false_key = thData->false_key;
  char *message = thData->message;
  unsigned long long int count = thData->start;

  char new_message[100] = {0};

  unsigned char hash_message[SHA256_DIGEST_LENGTH];
  uint16_t index, index_max = 0;

  SHA256_CTX ctx;

  sprintf(new_message, "%s + %llu", message, count);

  int16_t i = 0;
  while(i < SHA256_DIGEST_LENGTH) {
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, new_message, strlen(new_message));
    SHA256_Final(hash_message, &ctx);

    for(int j = 0; j < 7; ++j) {
      index = (i*8 + j)*BlockByteSize;
      if((hash_message[i] & (1 << (7 - j))) &&
          !check_hash(&false_key->one[index], &public->one[index], BlockByteSize)) {
        if(index > index_max) {
          index_max = index;
          printf("thread: %d, Block Max: %d, counter: %llu\n", id, 8*i + j, count);
        }
        sprintf(new_message, "%s + %llu", message, ++count);
        i = -1;
        break;
      } else if(!(hash_message[i] & (1 << (7 - j))) &&
          !check_hash(&false_key->zero[index], &public->zero[index], BlockByteSize)) {
        if(index > index_max) {
          index_max = index;
          printf("thread: %d, Block Max: %d, counter: %llu\n", id, 8*i + j, count);
        }
        sprintf(new_message, "%s + %llu", message, ++count);
        i = -1;
        break;
      }
    }
    i++;
  }

  nounce = count;

  return 0;
}


unsigned long long int attack_lamport(attackArgs *values) {

  if(values->nThreads <= 0) {
    printf("The number of threads must be greater than 0\n");
    exit(EXIT_FAILURE);
  }

  key false_key;
  memset(false_key.one, 0, BlockByteSize*256);
  memset(false_key.zero, 0, BlockByteSize*256);

  copy_signature(values->pub, values->signs, &false_key);

  printf("Searching a Nounce...\n");

  // Creating threads
  threadData **threads_args;
  threads_args = malloc((values->nThreads)*sizeof(threadData *));
  pthread_t **threads;
  threads = malloc((values->nThreads)*sizeof(pthread_t *));

  unsigned long long int split = 18446744073709551615UL - (18446744073709551615UL/(values->nThreads));
  int i;
  for(i = 0; i < (values->nThreads - 1); ++i) {
    threads_args[i] = malloc(sizeof(threadData));
    threads_args[i]->threadID = i;
    threads_args[i]->public = values->pub;
    threads_args[i]->false_key = &false_key;
    threads_args[i]->message = values->message;
    threads_args[i]->start = split*i;

    threads[i] = malloc(sizeof(pthread_t *));
    pthread_create(threads[i], NULL, forge_signature, threads_args[i]);
  }

  // One thread will be the program itself
  threads_args[i] = malloc(sizeof(threadData));
  threads_args[i]->threadID = i;
  threads_args[i]->public = values->pub;
  threads_args[i]->false_key = &false_key;
  threads_args[i]->message = values->message;
  threads_args[i]->start = split*i;

  forge_signature(threads_args[i]);

  for(i = 0; i < (values->nThreads - 1); ++i) {
    free(threads[i]);
    free(threads_args[i]);
  }
  free(threads_args[i]);
  free(threads);
  free(threads_args);

  char message_forged[100] = {0};
  sprintf(message_forged, "%s + %llu", values->message, nounce);

  Sign(&false_key, message_forged, values->forge);

  return nounce;
}
