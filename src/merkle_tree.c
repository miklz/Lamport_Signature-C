#include <stdlib.h>
#include <string.h>

#include "signature.h"
#include "merkle_tree.h"

struct Leaf_t {
    key *prv;
    key *pub;
};

struct Node_t {
    node_t *upper_node;
    node_t *right_node;
    node_t *left_node;
    leaf_t *leaf;
    uint8_t *data;
};

void build_tree(node_t *root, uint16_t n_messages) {

  leaf_t *leaf = malloc(sizeof(leaf)*n_messages);

  for(int i = 0; i < n_messages; ++i) {
    GenerateKeys(leaf[i].prv, leaf[i].pub);
  }

  // Incomplete implementation
  root->right_node = NULL;
  root->left_node = NULL;
}

int add_node(node_t *node, node_t *right_node, node_t *left_node) {

  // Connecting right and left node
  node->right_node = right_node;
  node->left_node = left_node;

  // Using the data of left and right node only if they exist
  uint8_t *temp;
  int array_size;
  if((right_node->data != NULL) && (left_node->data != NULL)) {
    array_size = 2*SHA256_DIGEST_LENGTH;
    temp = malloc(array_size);
    if(temp == NULL) {
      return NODE_ERROR;
    }
    memcpy(temp, right_node->data, SHA256_DIGEST_LENGTH);
    memcpy(temp + SHA256_DIGEST_LENGTH, left_node->data, SHA256_DIGEST_LENGTH);
  } else if(right_node->data != NULL) {
    array_size = SHA256_DIGEST_LENGTH;
    temp = malloc(array_size);
    memcpy(temp, right_node->data, array_size);
  } else {
    array_size = SHA256_DIGEST_LENGTH;
    temp = malloc(array_size);
    memcpy(temp, left_node->data, array_size);
  }

  // Performing hash of the hash of the nodes
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, temp, array_size);
  node->data = malloc(SHA256_DIGEST_LENGTH);
  if(node->data == NULL) {
    return NODE_ERROR;
  }
  SHA256_Final(node->data, &ctx);

  free(temp);

  return NODE_SUCCESS;
}

void free_node(node_t *node) {

  free(node->leaf);
  free(node->right_node);
  free(node->left_node);
  free(node->data);
}

void free_tree(node_t *node) {

  free(node);
}
