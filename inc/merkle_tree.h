#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include "stdint.h"

#define KEY_AVAILABLE 1
#define KEY_NOT_AVAILABLE 0

#define NODE_ERROR 0
#define NODE_SUCCESS 1

typedef struct Leaf_t leaf_t;
typedef struct Node_t node_t;

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
 * @Returns: None.
 */
node_t* build_tree(uint16_t n_messages);

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
 *  The number of nodes to make are passed to the function, and the node made
 * is returned
 *
 * @Returns: None.
 */
node_t* bootstrap_tree(int n);

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
 * @Returns: pointer of int : Signature, public key, authentication nodes.
 */
uint8_t* merkle_sign(node_t *node, char *message);

/*
 * @Function:
 *  verify_prove.
 *
 * @Description:
 *  Check if the signature provide hashes to the public key.
 *
 * @Parameters:
 *  Merkle signature.
 *
 * @Returns: true or false if the signature matchs or not.
 */
uint8_t verify_prove(uint8_t* signature);

/*
 * @Function:
 *  free_tree;
 *
 * @Description:
 *  Delete the whole tree.
 *
 * @Parameters:
 *  Root node.
 *
 * @Returns:
 *  NODE_ERROR or NODE_SUCCESS depending if the operation
 *  was successful or not.
 */
void free_tree(node_t *node);

#endif
