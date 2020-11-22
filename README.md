# Lamport_Signature-C

This repository is to implement some of the functionalities of the
Lamport signature discussed in the course offered by the MIT
![Cryptocurrency Engineering and Design](https://ocw.mit.edu/courses/media-arts-and-sciences/mas-s62-cryptocurrency-engineering-and-design-spring-2018/index.htm).

I'm aiming to implement the Lamport signature using SHA-256 as hash
function and explore the risks in using the same private key for
more than one signature.

## Lamport Signature

So, the Lamport signature consists of a private key, a hash function
and a public key. The public key is generate from the private key
using a hash, and the private key is generate using a Pseudo Random
Number Generator (PRNG).

```
Section zero
private key     : [rz0] ---------- [rz1] ---------- ... ---------- [rz255]
                     |               |               |                |
hash function   : hash([rz0]) - hash([zr1]) ------- ... -------- hash([rz255])
                     |               |               |                |
public key      : [hz0] ---------- [hz1] ---------- ... ---------- [hz255]

Section one
private key     : [ro0] ---------- [ro1] ---------- ... ---------- [ro255]
                     |               |               |                |
hash function   : hash([ro0]) - hash([ro1]) ------- ... -------- hash([ro255])
                     |               |               |                |
public key      : [ho0] ---------- [ho1] ---------- ... ---------- [ho255]
```

It could be use any hash function to use this method, here I've chosen
to use the same as in the ![assignments](https://ocw.mit.edu/courses/media-arts-and-sciences/mas-s62-cryptocurrency-engineering-and-design-spring-2018/assignments/pset1-hash-based-signature-schemes/), that's, the SHA-256.

To sign a message we first hash the message and for each bit of the hash
we reveal the corresponding block.
Example: the bits of the message hashed are 1010011..., than we pass the blocks
([ro0], [rz1], [ro2], [rz3], [rz4], [ro5], [ro6], ...) so anyone can check
that this message originates from the same person which the public key belongs.
The process to check is straightforward, each block revealed is hashed and
compared with the public key, if they do match, than the signature's valid.

## Implementation

The private key consists of 2 sections of 256 blocks of 256 bits per block,
therefore the total size in bytes of the private key is 2.256.256/8 = 16384
Bytes, and since the hash function outputs 256 bits per input we also need
to store 16384 Bytes for the public key. In total we have 32 KBytes for each
pair of keys generated.

The length of each block of the private key could be less than the 256 bits,
but for security reasons it shouldn't, if each block had a size of 32 bits,
for example, the public key would still have 256 bits per block, but it
would be feasible in a modern computer to try out all the input
possibilities hashing it and compare with the public key to find the private
key in a modern computer. This is called a pre-image attack, so we need to
make unrealistic to run out all the input values just as in the outputs of
the hash function.

## Exploring the bad use of Lamport signature

If the same private key is used to sign more than one message, than, it is
possible for an attacker to sign its own message pretending to be the real
owner of the key. If the messages signed were random messages than with
4 messages is already possible to forge a new message in a standard computer.
This is possible because each signature reveals parts of the private key,
colecting the blocks revealed from the signatures gives a flexibility for
an attacker to chose specific messages that use only those blocks.

## Improvement using Merkle Tree

Since is proven possible to hack a signature if the private key is used more
than once we should never do that. Therefore, if we want to sign 4 messages
we'll have to publish a 64 KB public key, and signing a message would have to
say wich public key those blocks are refering to.
But with merkle tree we only need to publish 32 B that is our public key, or root,
and provide a validation methode so the verifyer can check that private key is
indeed part of that tree.
