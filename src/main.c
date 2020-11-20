#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "signature.h"
#include "signature_attack.h"

#define N_SIGNATURES 4
#define N_THREADS 2

int main(void) {
  key private, public;

  GenerateKeys(&private, &public);

  char **message_i;

  message_i = malloc(N_SIGNATURES * sizeof(char *));

  signatures signs;
  signs.n = N_SIGNATURES;
  signs.sign = malloc(N_SIGNATURES * sizeof(uint8_t *));

  for(int i = 0; i < N_SIGNATURES; ++i) {
    message_i[i] = malloc(sizeof("Message[00]"));
    sprintf(message_i[i], "Message[%d]", i);
    signs.sign[i] = malloc(256 * BlockByteSize * sizeof(uint8_t));
    Sign(&private, message_i[i], signs.sign[i]);
    if(!Verify(&public, message_i[i], signs.sign[i])) {
      printf("Wrong sign\n");
      return 1;
    }
  }

  for(int i = 0; i < N_SIGNATURES; ++i) {
    free(message_i[i]);
  }
  free(message_i);

  printf("Keys Signed\n");

  char message_to_forge[] = {"Message forged - mikael_ferraz@hotmail.com"};
  uint8_t false_signature[256*BlockByteSize];

  printf("Forging Signature... \n");

  attackArgs values;
  values.nThreads = N_THREADS;
  values.public = &public;
  values.signs = &signs;
  values.message = message_to_forge;
  values.forge = false_signature;

  unsigned long long int nounce = attack_lamport(&values);
  char *message_forged = malloc(strlen(message_to_forge)*sizeof(char) + 2*sizeof(unsigned long long int));
  memset(message_forged, 0, strlen(message_to_forge)*sizeof(char) + 2*sizeof(unsigned long long int));
  sprintf(message_forged, "%s + %llu", message_to_forge, nounce);
  printf("%s\n", message_forged);
  printf("Done\n");

  for(int i = 0; i < N_SIGNATURES; ++i) {
    free(signs.sign[i]);
  }
  free(signs.sign);

  if(Verify(&public, message_forged, false_signature)) {
    printf("The signature was successfully forged\n");
  } else {
    printf("Attack was unsuccessful\n");
  }

  printf("Done\n");

  return 0;
}