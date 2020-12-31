#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "signature.h"
#include "merkle_tree.h"
#include "signature_attack.h"

#define N_SIGNATURES 5
#define N_THREADS 2

void test_signature(void) {

  printf("Testing the signature implementation\n");

  key private, public;

  GenerateKeys(&private, &public);

  char message[] = "Validating signature";
  uint8_t sign[256*BlockByteSize];

  Sign(&private, message, sign);

  int ret = Verify(&public, message, sign);

  if(ret) {
    printf("Signature successfully signed\n");
  } else {
    printf("Bad signature\n");
  }
}

void test_forging_signature(void) {

  printf("Exploring the bad use of Lamport signature\n");

  key private, public;

  GenerateKeys(&private, &public);

  char **message_i;

  message_i = malloc(N_SIGNATURES * sizeof(char *));

  signatures signs;
  signs.n = N_SIGNATURES;
  signs.sign = malloc(N_SIGNATURES * sizeof(uint8_t *));

  for(int i = 0; i < N_SIGNATURES; ++i) {
    message_i[i] = malloc(sizeof("Message[00]\n"));
    sprintf(message_i[i], "Message[%d]\n", i);
    signs.sign[i] = malloc(256 * BlockByteSize * sizeof(uint8_t));
    Sign(&private, message_i[i], signs.sign[i]);
    if(!Verify(&public, message_i[i], signs.sign[i])) {
      printf("Wrong sign\n");
      return;
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
  values.pub = &public;
  values.signs = &signs;
  values.message = message_to_forge;
  values.forge = false_signature;

  clock_t time = clock();

  unsigned long long int nounce = attack_lamport(&values);

  time = clock() - time;
  printf("It took %fs with %d threads to forge the signature\n", ((double)time)/CLOCKS_PER_SEC, N_THREADS);
  char message_forged[100] = {0};
  sprintf(message_forged, "%s + %llu", message_to_forge, nounce);
  printf("%s\n", message_forged);

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

}

void test_merkle_tree(void) {
  tree_t *merkle_tree = build_tree(8);

  print_tree(get_root(merkle_tree));

  char message[] = "Testing Merkle signature scheme";
  merkle_sign *merkle_test;
  for(int i = 0; i < 9; ++i) {
    merkle_test = merkle_signature(merkle_tree, message);

    if(merkle_test == NULL) {
      printf("No more keys available\n");
      free_tree(merkle_tree);
      return;
    }

    if(verify_prove(get_public_hash(merkle_tree), message, merkle_test)) {
      printf("The signature is within the tree\n");
    } else {
      printf("The prove doesn't match with the public hash\n");
    }
    free_merkle_signature(merkle_test);
  }

  free_tree(merkle_tree);
}

int main(void) {

  uint8_t k = 0;
  srand(k);

  test_signature();

  test_forging_signature();

  test_merkle_tree();

  return 0;
}
