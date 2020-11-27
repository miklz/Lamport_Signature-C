#include <stdlib.h>
#include <string.h>

#include "signature.h"
#include "merkle_tree.h"

struct Leaf_t {
  key *prv;
  key *pub;
};

struct Node_t {
  node_t *right_node;
  node_t *left_node;
  leaf_t *leaf;
  uint8_t data[SHA256_DIGEST_LENGTH];
};

void build_tree(node_t *root, uint16_t n_messages) {

  leaf_t *leaf = malloc(sizeof(leaf_t)*n_messages);
  node_t *nodes = malloc(sizeof(node_t)*n_messages);

  for(int i = 0; i < n_messages; i += 2) {
    GenerateKeys(leaf[i].prv, leaf[i].pub);
    node_set_leaf(&nodes[i], &leaf[i]);
  }

  bootstrap_tree(root, nodes, n_messages/2);
}

void node_set_leaf(node_t *node, leaf_t *leaf) {

  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, leaf->pub, 256*BlockByteSize);
  SHA256_Final(node->data, &ctx);
}

void bootstrap_tree(node_t *root, node_t *nodes, int n) {

  if(n == 1) {
    add_node(root, &nodes[0], &nodes[1]);
    return;
  } else {
    node_t *more_nodes = malloc(sizeof(node_t)*n);
    for(int i = 0; i < n; i += 2) {
      add_node(&more_nodes[i%2], &nodes[i], &nodes[i+1]);
    }
    bootstrap_tree(root, more_nodes, n/2);
  }
}

int add_node(node_t *node, node_t *right_node, node_t *left_node) {

  // Connecting right and left node
  node->right_node = right_node;
  node->left_node = left_node;

  // Left and right nodes will always exist
  uint8_t *temp;
  temp = malloc(SHA256_DIGEST_LENGTH);
  if(temp == NULL) {
    return NODE_ERROR;
  }
  memcpy(temp, right_node->data, SHA256_DIGEST_LENGTH);
  memcpy(temp + SHA256_DIGEST_LENGTH, left_node->data, SHA256_DIGEST_LENGTH);

  // Performing hash of the hash of the nodes
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, temp, 2*SHA256_DIGEST_LENGTH);
  SHA256_Final(node->data, &ctx);

  free(temp);

  return NODE_SUCCESS;
}

void free_node(node_t *node) {

  free(node->leaf);
  node->leaf = NULL;
  free(node->right_node);
  node->right_node = NULL;
  free(node->left_node);
  node->left_node = NULL;
}

void free_tree(node_t *node) {

  if(node->left_node != NULL) {
    free_tree(node->left_node);
  }
  if (node->right_node != NULL) {
    free_tree(node->right_node);
  }
  free_node(node);
  free(node);
}
