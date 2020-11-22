#include "stdint.h"

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
void build_tree(node_t *root, uint16_t n_messages);

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
 *  free_node
 *
 * @Description:
 *  Delete a specific node, releasing the memory used.
 *
 * @Parameters:
 *  Node to be deleted.
 *
 * @Returns:
 *  NODE_ERROR or NODE_SUCCESS depending if the operation
 *  was successful or not.
 */
void free_node(node_t *node);

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
