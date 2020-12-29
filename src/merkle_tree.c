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

struct Tree_t {
  node_t *root;
  leaf_t **keys;
  uint16_t key_ctrl;
};

struct Merkle_sign {
  uint8_t *sign;
  uint16_t size;
};

tree_t* build_tree(uint16_t n_messages) {

  tree_t *merkle_tree = malloc(sizeof(tree_t));

  // allocate the quantity of addresses to store keys
  merkle_tree->keys = malloc(n_messages*sizeof(leaf_t*));

  // How many keys there's in the tree
  merkle_tree->key_ctrl = 0;

  merkle_tree->root = bootstrap_tree(merkle_tree, n_messages);

  return merkle_tree;
}

void node_set_leaf(node_t *node, leaf_t *leaf) {

  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, &leaf->pub, 256*BlockByteSize);
  SHA256_Final(node->data, &ctx);

  leaf->parent = node;
  leaf->available = KEY_AVAILABLE;
}

node_t* bootstrap_tree(tree_t *tree, int n) {

  node_t *node = malloc(sizeof(node_t));

  if(node == NULL) {
    printf("Can't allocate memory for the node\n");
    exit(EXIT_FAILURE);
  }

  if(n != 1) {
    node->leaf = NULL;
    node->left_node = bootstrap_tree(tree, n/2);
    node->right_node = bootstrap_tree(tree, n/2);
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

  // Increase the number of keys stored in the tree
  tree->keys[tree->key_ctrl++] = node->leaf;

  return node;
}

node_t* get_root(tree_t *tree) {
  return tree->root;
}

uint8_t* get_public_hash(tree_t *tree) {
  return tree->root->data;
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

merkle_sign* merkle_signature(tree_t *tree, char *message) {

  int i;

  for(i = 0; i < tree->key_ctrl; ++i) {
    if(tree->keys[i]->available == KEY_AVAILABLE) {
      break;
    }
  }

  if(i == tree->key_ctrl) {
    return NULL;
  }

  merkle_sign *signature = malloc(sizeof(merkle_sign));
  signature->sign = malloc(BlockByteSize*256);
  signature->size = BlockByteSize*256;
  Sign(&tree->keys[i]->prv, message, signature->sign);
  signature->sign = realloc(signature->sign, signature->size + sizeof(key));
  memcpy(signature->sign + signature->size, (uint8_t *) &tree->keys[i]->pub, sizeof(key));
  signature->size = signature->size + sizeof(key);

  construct_signature(tree->root->data, tree->keys[i]->parent, signature);

  return signature;
}

void construct_signature(uint8_t *pub_hash, node_t *node, merkle_sign *sign) {

  if(memcmp(node->data, pub_hash, SHA256_DIGEST_LENGTH)) {
    sign->sign = realloc(sign->sign, sign->size + SHA256_DIGEST_LENGTH);
    if(node->upper_node->right_node != node) {
      memcpy(sign->sign + sign->size, node->upper_node->right_node->data, SHA256_DIGEST_LENGTH);
    } else {
      memcpy(sign->sign + sign->size, node->upper_node->left_node->data, SHA256_DIGEST_LENGTH);
    }
    sign->size = sign->size + SHA256_DIGEST_LENGTH;
    construct_signature(pub_hash, node->upper_node, sign);
  }
}

uint8_t verify_prove(uint8_t *pub, char* message, merkle_sign* signature) {

  key leaf_key;
  memcpy(&leaf_key, signature->sign + BlockByteSize*256, sizeof(key));
  if(Verify(&leaf_key, message, signature->sign)) {
    uint8_t temp[2*SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, &leaf_key, sizeof(key));
    SHA256_Final(temp, &ctx);

    for(int i = BlockByteSize*256 + sizeof(key); i < signature->size; i += SHA256_DIGEST_LENGTH) {
      memcpy(temp+SHA256_DIGEST_LENGTH, &signature->sign[i], SHA256_DIGEST_LENGTH);
      SHA256_Init(&ctx);
      SHA256_Update(&ctx, temp, SHA256_DIGEST_LENGTH);
      SHA256_Final(temp, &ctx);
    }

    if(!memcmp(temp, pub, SHA256_DIGEST_LENGTH)) {
      return 1;
    }
  }

  return 0;
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

void free_tree(tree_t *tree) {

  free_node(tree->root);
  free(tree->keys);
  tree = NULL;
}

void free_node(node_t *node) {

  if(node->left_node != NULL) {
    free_node(node->left_node);
  }
  node->left_node = NULL;
  if (node->right_node != NULL) {
    free_node(node->right_node);
  }
  node->right_node = NULL;
  if(node->leaf != NULL) {
    free(node->leaf);
    node->leaf = NULL;
  }
  free(node);
  node = NULL;
}
