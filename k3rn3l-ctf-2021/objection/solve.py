from pwn import remote, context
from hashlib import sha256
import json

def H(m):
    """ Return integer hash of byte message. """
    return int.from_bytes(sha256(m).digest(), 'big')

def bake(m, r, s, pk):
    return json.dumps({ 'm' : m.hex(), 'r' : r , 's' : s, 'pk': pk })

mA = b'I, Authenticator Alice, do not concur with the hoarding of flags.'
mC = b'I, Certifier Carlo, do not concur with the hoarding of flags.'
hA = H(mA)
hC = H(mC)

def main():
    io = remote('ctf.k3rn3l4rmy.com', 2240)
    io.recvuntil('P = ')
    p = int(io.recvline())
    io.recvuntil('Q = ')
    q = int(io.recvline())
    io.recvuntil('G (default) = ')
    g = int(io.recvline())

    print(f'{p = }')
    print(f'{q = }')
    print(f'{g = }')

    # Set generators
    def set_gen(tgt, val):
        io.sendlineafter('>> ', 'P')
        io.sendlineafter(': ', str(tgt))
        io.sendlineafter(': ', str(val))
        io.recvuntil('key: ')
        return int(io.recvline())

    pkA = set_gen(1, '')
    print(f'{pkA = }')

    pkC = set_gen(2, pkA)
    print(f'{pkC = }')

    b = (pkC * pkA % p % q) * pow(hA, -1, q) % q
    print(f'{b   = }')

    set_gen(3, pow(pkC, b, p))

    # Forge Carlo
    io.sendlineafter('>> ', 'S')
    r = pkC % q
    s = (hC*b + r) % q
    io.sendlineafter('pk): ', bake(mC, r, s, pkC))

    # Forge Alice
    io.sendlineafter('>> ', 'S')
    s = r = pkC * pkA % p % q
    io.sendlineafter('pk): ', bake(mA, r, s, pkA))

    io.interactive()

main()