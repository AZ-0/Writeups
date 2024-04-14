from math import gcd
from pwn import remote, process, context
context.log_level = 'debug'

def recv():
    io.recvuntil(b' = ')
    return int(io.recvline(False))

# io = process(['python3', 'el-gamal-fait-2.py'])
io = remote('challenges.france-cybersecurity-challenge.fr', 2152)

p = recv()
g = recv()
y = recv()
m = recv()
assert g == 2
assert (p-1) % 4 == 0

t = (p-1)//4
assert pow(g, t, p) == p-1

r = pow(g, t-1, p)
# assert r == 2*t
assert pow(y, r, p) == 1

print('obstruction:', gcd( t-1,  p-1 ))

s = m * pow(t-1, -1, p-1) % (p-1)
assert pow(r, s, p) == pow(g, m, p)

io.sendlineafter(b'>>> ', str(r).encode())
io.sendlineafter(b'>>> ', str(s).encode())
io.interactive()