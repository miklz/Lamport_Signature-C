
#include <openssl/sha.h>

#define BlockByteSize 32

typedef struct Key {
  uint8_t zero[BlockByteSize*256];
  uint8_t one[BlockByteSize*256];
} key;

/*
 * @Function:
 *  GenerateKeys
 *
 * @Description:
 *  It generetes a key pair, the private key is random. But the
 *  public key is a sha256 hash of the private key.
 *
 * @Parameters:
 *  The public key and private key to store the keys generated.
 *
 * @Return: None.
 */
void GenerateKeys(key* prv, key* pub);

/*
 * @Function:
 *  Sign
 *
 * @Description:
 *  Signs the message, it copy's some blocks of the private key
 *  depending on the message.
 *
 * @Parameters:
 *  The private key, the message to be sign and a pointer to
 *  store the blocks of the private key.
 *
 * @Return: None.
 */
void Sign(key* prv, char* message, uint8_t *sign);

/*
 * @Function:
 *  Sign
 *
 * @Description:
 *  Performs the hash on a specific block and compares with the hash
 *  expected.
 *
 * @Parameters:
 *  The array, the hash expected (some part of the public key), the 
 *  size of the block.
 *
 * @Return: 1 if they match and 0 if they don't.
 */
int check_hash(uint8_t *block, uint8_t *hash, int n);

/*
 * @Function:
 *  Verify
 *
 * @Description:
 *  Check if the part's of the private key match the public key according
 *  with the message.
 *
 * @Parameters:
 *  The public key, the message and the sign.
 *
 * @Return: 1 if they match and 0 if they don't.
 */
int Verify(key* pub, char* message, uint8_t *sign);

