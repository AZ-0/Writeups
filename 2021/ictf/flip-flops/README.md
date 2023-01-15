# Flip Flops
#### **Category:** Crypto
#### **Author:** Eth007
#### **Points:** 100
#### **Description:**
> Yesterday, Roo bought some new flip flops. Let's see how good at flopping you are.
#### **Attachments:** [flop.py](./flop.py)

## Symbols

| Symbol | Meaning |
| :----: | :------ |
| ⊕     | Bitwise [XOR](https://en.wikipedia.org/wiki/Bitwise_operation#XOR) |
| \|\|   | Block Concatenation |

## Understanding the challenge

We can perform up to 3 queries, each corresponding to either of the following:

1. Encrypt an arbitrary plaintext that does not contain "gimmeflag". The plaintext is padded with PKCS#7 before encryption. We are given the ciphertext.
1. Decrypt an arbitrary ciphertext. If the plaintext contains "gimmeflag", we are given the flag. We are not given the plaintext.

All encryption/decryption operations are done under [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)-[CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)) with fixed unknown key and iv. The server reads the plaintext/ciphertext in hex so that we can send any bytes.

**Goal:** Forge a ciphertext


## Solving the challenge

![CBC Encryption](https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/900px-CBC_encryption.svg.png "Wikipedia's CBC Encryption")

Due to how CBC works, we can get one block of ciphertext to decrypt to any plaintext with the following process:

Let `p` be the desired plaintext block. Let `p1` and `p2` any other plaintext blocks. We call `ENC(x)` the AES encryption operation, independent of mode. That is, it corresponds to the "block cipher encryption" box in the image. We call `DEC(x)` the inverse operation.

First, encrypt `p1 || p2`. We call the resulting ciphertext `c1 || c2`. Now as per CBC, we have the following equations:

- `c1 = ENC(p1 ⊕ iv)`
- `c2 = ENC(p2 ⊕ c1)`

Now can we use that to somehow find the `c` such that `DEC(c) = p` ? The answer is no! We'll use and abuse CBC instead.

![CBC Decryption](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/900px-CBC_decryption.svg.png "Wikipedia's CBC Decryption")

A nice set of properties to remember about XOR is that it is associative [`(a ⊕ b) ⊕ c = a ⊕ (b ⊕ c)`], self-inverse [`a ⊕ a = 0`], and possesses a neutral element [`a ⊕ 0 = a`].
Now this can be useful, because `DEC(c2) = p2 ⊕ c1` by definition.
If we somehow manage to XOR `DEC(c2)` with `p2 ⊕ c1 ⊕ p`, the `p2 ⊕ c1` part would cancel out and we would be left with `p` only ─ just what we want!

But is there a way to perform that XOR? Yes!
If we send `(p2 ⊕ c1 ⊕ p) || c2` to the server for decryption, CBC will ensure that the following happens:

Let `P1` the first decrypted block, `P2` the second.

- `P1 = DEC(p2 ⊕ c1 ⊕ p) ⊕ iv`
- `P2 = DEC(c2) ⊕ p2 ⊕ c1 ⊕ p = p2 ⊕ c1 ⊕ p2 ⊕ c1 ⊕ p = p`

Neat.

## Solve script

We nearly got everything we want, there are only some details left to implement. One thing to consider is that before encryption, plaintexts are padded with [PKCS#7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7). That means, if we merrily send our 16-bytes plaintexts, a block consisting of only `0x10` repeated 16 times will get appended! Luckily that's not a problem, as we can just consider the first two encrypted blocks and forget about the rest.

For simplicity, I took `p1 = p2 = 0` to have less things to XOR together:
```py
from Crypto.Util.Padding import pad
from pwn import remote, xor

p = pad(b'gimmeflag', 16)
p1 = p2 = b'\0'*16

r = remote('chal.imaginaryctf.org', 42011)
r.sendlineafter('> ', '1') # Option: Encrypt
r.sendlineafter(': ', (p1+p2).hex())

raw = bytes.fromhex(r.recvline(False).decode())
c1 = raw[00:16]
c2 = raw[16:32]

r.sendlineafter('> ', '2') # Option: Decrypt
r.sendlineafter(': ', (xor(c1, p) + c2).hex()) # We don't need to xor p2 = 0
r.interactive()
```