#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include "stdint.h"

#define KEY_AVAILABLE 1
#define KEY_NOT_AVAILABLE 0

#define NODE_ERROR 0
#define NODE_SUCCESS 1

typedef struct Leaf_t leaf_t;
typedef struct Node_t node_t;
typedef struct Tree_t tree_t;
typedef struct Merkle_sign merkle_sign;

/*
 * @Function:
 *  build_tree
 *
 * @Description:
 *  Constructs the tree from the bottom up.
 *  The root node'll have the public hash.
 *  The depth of the tree will depend on the number of messages
 *  that is pretend to sign.
 *
 * @Parameters:
 *  The node that will be the root of the tree.
 *  The number of messages that we want to sign (must be a power of two).
 *
 * @Returns: The merkle tree.
 */
tree_t* build_tree(uint16_t n_messages);

/*
 * @Function:
 *  node_set_leaf
 *
 * @Description:
 *  It sets a leaf to a node, performs a hash of the public key
 *  and stores the hash result in the data field of the node.
 *
 * @Parameters:
 *  The base node and the leaf that stores the public/private key.
 *
 * @Returns: None.
 */
void node_set_leaf(node_t *node, leaf_t *leaf);

/*
 * @Function:
 *  bootstrapp_tree
 *
 * @Description:
 *  Recursive function that constructs the tree from the base.
 *
 * @Parameters:
 *  The tree, and the number of nodes to be made are passed to the function
 *
 * @Returns: The node created is return.
 */
node_t* bootstrap_tree(tree_t *tree, int n);

/*
 * @Function:
 *  get_root
 *
 * @Description:
 *  Returns the root of the tree, the first node
 *
 * @Parameters:
 *  The tree
 *
 * @Returns: The root node.
 */
node_t* get_root(tree_t *tree);

/*
 * @Function:
 *  get_public_hash
 *
 * @Description:
 *  Returns the public hash
 *
 * @Parameters:
 *  The tree
 *
 * @Returns: The hash.
 */
uint8_t* get_public_hash(tree_t *tree);

/*
 * @Function:
 *  add_node
 *
 * @Description:
 *  Adds a node and conects with his childs
 *
 * @Parameters:
 *  The father and child nodes.
 *
 * @Returns:
 *  NODE_ERROR or NODE_SUCCESS depending if the operation
 *  was successful or not.
 */
int add_node(node_t *node, node_t *right_node, node_t *left_node);

/*
 * @Function:
 *  print_tree
 *
 * @Description:
 *  It'll print the child nodes hashes and the parent hash exacly how its on
 *  the tree and computing the hashes of the childs to see if they match with
 *  the parent node hash
 *
 * @Parameters:
 *  The root node
 *
 * @Returns: None
 */
void print_tree(node_t *node);

/*
 * @Function:
 *  merkle_sign
 *
 * @Description:
 *  returns the parts of the private key just as the public key and the verifying
 *  nodes hashes
 *
 * @Parameters:
 *  Root node and the message to sign
 *
 * @Returns: The merkle signature, with the signature and size of the signature.
 */
merkle_sign* merkle_signature(tree_t *tree, char *message);

/*
 * @Function:
 *  construct_signature
 *
 * @Description:
 *  Recursive function that copys the hashes of the adjacents nodes
 *
 * @Parameters:
 *  Public hash (goal), the node to start and a merkle struct (array with size)
 *
 * @Returns: None
 */
void construct_signature(uint8_t *pub_hash, node_t *node, merkle_sign *sign);

/*
 * @Function:
 *  verify_prove.
 *
 * @Description:
 *  Check if the signature provide hashes to the public key.
 *
 * @Parameters:
 *  Public key, the message and the merkle signature.
 *
 * @Returns: true or false if the signature matchs or not.
 */
uint8_t verify_prove(uint8_t *pub, char* message, merkle_sign* signature);

/*
 * @Function:
 *  free_merkle_signature;
 *
 * @Description:
 *  Free the signature within the structure and the structure pointer
 *
 * @Parameters:
 *  Merkle signature.
 *
 * @Returns: None
 */
void free_merkle_signature(merkle_sign* signature);

/*
 * @Function:
 *  free_tree;
 *
 * @Description:
 *  Chop the tree
 *
 * @Parameters:
 *  Tree.
 *
 * @Returns: None
 */
void free_tree(tree_t *tree);

/*
 * @Function:
 *  free_node;
 *
 * @Description:
 *  Delete the whole tree.
 *
 * @Parameters:
 *  Root node.
 *
 * @Returns: None
 */
void free_node(node_t *node);

#endif
