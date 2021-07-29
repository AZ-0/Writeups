#!/usr/local/bin/python
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