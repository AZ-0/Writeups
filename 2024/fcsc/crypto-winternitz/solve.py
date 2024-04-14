from sage.all import *
from hashlib import sha256
from ast import literal_eval
from pwn import process, remote, context


W = 257
msglen = 20
siglen = 40
n1 = siglen // 256 + 1 # = 1
n2 = W // 256 + 1      # = 2
Support = [
              8,  17,  26,  32,  52,  53,  57,  58,
             59,  63,  64,  66,  67,  71,  73,  76,
             79,  81, 111, 115, 132, 135, 141, 144,
            151, 157, 170, 176, 191, 192, 200, 201,
            202, 207, 216, 224, 228, 237, 241, 252,
        ]


def _byte_xor(b1, b2):
    assert len(b1) == len(b2), "Error: byte strings of different length."
    return bytes([x ^ y for x, y in zip(b1, b2)])


def _encoding(msg):
    w = [0] * len(Support)
    for i in range(len(Support)):
        for j in range(len(msg)):
            # Constant coefficient is zero
            w[i] += msg[j] * Support[i] ** (j + 1)
        w[i] %= W
    return w


def _H(s, m, i, j):
    return sha256(
        _byte_xor(
            s,
            sha256(
                m + i.to_bytes(n1) + j.to_bytes(n2)
            ).digest()
        )
    ).digest()


def recv():
    io.recvuntil(b' = ')
    return literal_eval(io.recvline(False).decode())


# io = process(['python3', 'winternitz-is-coming.py'])
io = remote('challenges.france-cybersecurity-challenge.fr', 2153)

message   = recv()
signature = list(recv())
pk        = list(recv())

signature = [bytes.fromhex(s) for s in signature]
pk[0] = bytes.fromhex(pk[0])
pk[1] = [bytes.fromhex(s) for s in pk[1]]

# encoding: message évalué en Support, en tant que polynôme
# w[i] = msg_as_poly(Supp[i])

eqs = [
    [ pow(s, j+1, W) for j in range(msglen) ]
    for s in Support
]

G = matrix(GF(W), eqs).T

print('msg:', message)
w = _encoding(message)
m = [256 - wi for wi in w]

sm = sorted(m)
perm = [-1]*40
seen = {}
for i, j in enumerate(sm):
    l = seen.get(j, -1)
    k = m.index(j, l+1)
    perm[i] = k
    seen[j] = k
assert matrix(sm) == matrix([m]).matrix_from_columns(perm)

Gp = G.matrix_from_columns(perm)
E = Gp.echelon_form()
S = matrix([
    Gp.solve_left(Ei)
    for Ei in E
])
assert S*Gp == E
assert S.is_invertible()

print(E.str())

δ = vector(QQ, [-mi//2 for mi in sm] + [1])
D = matrix.diagonal(QQ, [100]*20 + [10]*20 + [10000]).dense_matrix()
M = matrix(δ).stack(E.change_ring(QQ).stack(matrix.diagonal([W]*40)).augment(matrix(QQ, 60, 1))).dense_matrix()
M = ((M*D).LLL()/D).change_ring(GF(W))

for row in M:
    if row == 0: continue
    row -= δ*row[-1]
    print('-'*100)
    print(matrix(sm))
    print(matrix(row))
    print('   ' + '   '.join(['!', ' '][ei <= mi] for mi, ei in zip(sm, row)))

# Last vector of this matrix!!!
st = [1,   8,   6,   9,   6,   9,   8,   6,  11,  11,  12,  18,  21,  22,  22,  24,  23,  24,  26,  31,  32,  17,  54,  16,  70,  41,  41, 117,  56,  70,  69,  56, 106,  65,  94, 102,  96, 124, 156, 136,]
assert vector(GF(W), st) in Gp.image()

inv = [perm.index(i) for i in range(40)]
assert matrix(m) == matrix([sm]).matrix_from_columns(inv)

t = matrix(GF(W), st).matrix_from_columns(inv)[0]
m = G.solve_left(t)
print('m:', m)

mymsg = list(message)
for i, mi in enumerate(m):
    mymsg[i] = (mymsg[i] + int(mi)) % W

myw = _encoding(mymsg)

print('enc:', matrix(w))
print('enc:', matrix(myw))

mask_seed = pk[0]
S = signature
for i in range(siglen):
    for j in range(w[i] + 1, myw[i] + 1):
        S[i] = _H(S[i], mask_seed, i, j)

io.sendlineafter(b'>>> ', bytes(mymsg).hex().encode())
io.sendlineafter(b'>>> ', str([s.hex() for s in S]).encode())

print('YAAAAAY')
io.interactive()