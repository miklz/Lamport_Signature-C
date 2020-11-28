#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "signature.h"
#include "merkle_tree.h"

struct Leaf_t {
  key prv;
  key pub;
  node_t *parent;
};

struct Node_t {
  node_t *upper_node;
  node_t *right_node;
  node_t *left_node;
  leaf_t *leaf;
  uint8_t data[SHA256_DIGEST_LENGTH];
};

node_t* build_tree(uint16_t n_messages) {

  node_t *nodes = malloc(sizeof(node_t)*n_messages);
  if(nodes == NULL) {
    printf("Can't allocate memory for the nodes\n");
    exit(EXIT_FAILURE);
  }

  for(int i = 0; i < n_messages; ++i) {
    nodes[i].leaf = malloc(sizeof(leaf_t));

    if(nodes[i].leaf == NULL) {
      printf("Can't allocate memory for the leaves\n");
      exit(EXIT_FAILURE);
    }

    GenerateKeys(&nodes[i].leaf->prv, &nodes[i].leaf->pub);
    node_set_leaf(&nodes[i], nodes[i].leaf);
  }

  return bootstrap_tree(nodes, n_messages/2);
}

void node_set_leaf(node_t *node, leaf_t *leaf) {

  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, &leaf->pub, 256*BlockByteSize);
  SHA256_Final(node->data, &ctx);

  leaf->parent = node;
}

node_t* bootstrap_tree(node_t *nodes, int n) {

  node_t *more_nodes = malloc(sizeof(node_t)*n);
  for(int i = 0; i <= n; i += 2) {
    add_node(&more_nodes[i/2], &nodes[i], &nodes[i+1]);
  }
  // If the last node was added return it!
  if(n == 1)
    return more_nodes;

  return bootstrap_tree(more_nodes, n/2);
}

int add_node(node_t *node, node_t *left_node, node_t *right_node) {

  // Connecting right and left node
  node->right_node = right_node;
  node->left_node = left_node;

  // Setting the parent node
  left_node->upper_node = node;
  right_node->upper_node = node;

  // Left and right nodes will always exist
  uint8_t *temp = malloc(2*SHA256_DIGEST_LENGTH);
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

void print_tree(node_t *node) {
  /*
  if(node->left_node != NULL) {
    print_tree(node);
  } else {
    return;
  }

  if(node->right_node != NULL) {
    print_tree(node);
  } else {
    return;
  }
  */

  printf("Right node hash: ");
  for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    printf("%d", node->right_node->data[i]);
  }
  printf("\n");

  printf("Left node hash: ");
  for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    printf("%d", node->left_node->data[i]);
  }
  printf("\n");

  printf("Node hash: ");
  for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    printf("%d", node->data[i]);
  }
  printf("\n");

  uint8_t hash_nodes[2*SHA256_DIGEST_LENGTH];
  uint8_t hash_result[SHA256_DIGEST_LENGTH];

  memcpy(hash_nodes, node->right_node->data, SHA256_DIGEST_LENGTH);
  memcpy(hash_nodes + SHA256_DIGEST_LENGTH, node->left_node->data, SHA256_DIGEST_LENGTH);

  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, hash_nodes, 2*SHA256_DIGEST_LENGTH);
  SHA256_Final(hash_result, &ctx);

  printf("Hash Result: ");
  for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    printf("%d", hash_result[i]);
  }
  printf("\n");

  if(!memcmp(hash_result, node->data, SHA256_DIGEST_LENGTH)) {
    printf("The node hash is correct\n");
  } else {
    printf("Problem with the node hash\n");
  }
}

void free_node(node_t *node) {

  if(node->leaf != NULL) {
    free(node->leaf);
    node->leaf = NULL;
  }
}

void free_tree(node_t *node) {

  if(node->left_node != NULL) {
    free_tree(node->left_node);
  }
  node->left_node = NULL;
  if (node->right_node != NULL) {
    free_tree(node->right_node);
  }
  node->right_node = NULL;
  free_node(node);
  free(node);
  node = NULL;
}
