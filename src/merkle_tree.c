#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "signature.h"
#include "merkle_tree.h"

struct Leaf_t {
  key prv;
  key pub;
  int available;
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
  return bootstrap_tree(n_messages);
}

void node_set_leaf(node_t *node, leaf_t *leaf) {

  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, &leaf->pub, 256*BlockByteSize);
  SHA256_Final(node->data, &ctx);

  leaf->parent = node;
  leaf->available = KEY_AVAILABLE;
}

node_t* bootstrap_tree(int n) {

  node_t *node = malloc(sizeof(node_t));

  if(node == NULL) {
    printf("Can't allocate memory for the node\n");
    exit(EXIT_FAILURE);
  }

  if(n != 1) {
    node->leaf = NULL;
    node->left_node = bootstrap_tree(n/2);
    node->right_node = bootstrap_tree(n/2);
    add_node(node, node->left_node, node->right_node);
    return node;
  }

  node->leaf = malloc(sizeof(leaf_t));
  node->left_node = NULL;
  node->right_node = NULL;

  if(node->leaf == NULL) {
    printf("Can't allocate memory for the leaf\n");
    exit(EXIT_FAILURE);
  }

  GenerateKeys(&node->leaf->prv, &node->leaf->pub);
  node_set_leaf(node, node->leaf);
  return node;
}

int add_node(node_t *node, node_t *left_node, node_t *right_node) {

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

  if(node->left_node != NULL) {
    print_tree(node->left_node);
  } else {
    return;
  }

  if(node->right_node != NULL) {
    print_tree(node->right_node);
  } else {
    return;
  }

  printf("Left node hash: ");
  for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    printf("%d", node->left_node->data[i]);
  }
  printf("\n");

  printf("Right node hash: ");
  for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    printf("%d", node->right_node->data[i]);
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

void free_tree(node_t *node) {

  if(node->left_node != NULL) {
    free_tree(node->left_node);
  }
  node->left_node = NULL;
  if (node->right_node != NULL) {
    free_tree(node->right_node);
  }
  node->right_node = NULL;
  if(node->leaf != NULL) {
    free(node->leaf);
    node->leaf = NULL;
  }
  free(node);
  node = NULL;
}
