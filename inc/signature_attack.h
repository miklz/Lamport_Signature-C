/*
 *  Author:
 *      Mikael F. Aldebrand.
 *  Purpose:
 *      To know the riscs in using the same
 *      private key to sign multiples messages.
 */

typedef struct Signatures {
  uint8_t n;
  uint8_t **sign;
} signatures;

typedef struct Attack {
  int nThreads;
  key *public;
  signatures *signs;
  char *message;
  uint8_t *forge;
} attackArgs;

/*
 * @Function:
 *  copy_signature
 *
 * @Description:
 *  It copy's the signatures used in each message.
 *
 * @Parameters:
 *  The public key to check what part of the private key it belongs.
 *  The signatures itself.
 *  The false private key that'll be copying the specific block of
 *  the signature
 *
 * @Return: None
 */
void copy_signature(key* public, signatures *clues, key *false_key);

/*
 * @Function:
 *  forge_signature
 *
 * @Description:
 *  Search for a nounce that satisfies the parts of the private key
 *  that was fed in the copy_signature function.
 *
 * @Parameters:
 *  Any parameter, but in my application there's a struct in the c file.
 *
 * @Return: Any, but in reality is none.
 */
void *forge_signature(void *args);

/*
 * @Function:
 *  attack_lamport
 *
 * @Description:
 *  It call's the functions in the right order and deals with parallelism.
 *
 * @Parameters:
 *  The public key, the signatures of the messages, the message to forge the
 *  signature and the pointer of bytes to store the signature forged.
 *
 * @Return: None.
 */
unsigned long long int attack_lamport(attackArgs *values);
