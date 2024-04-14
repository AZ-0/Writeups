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


io = process(['python3', 'winternitz-is-coming.py'])
# io = remote('challenges.france-cybersecurity-challenge.fr', 2153)

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

print('msg:', message)
w = _encoding(message)

suplen = len(Support)

M = matrix(QQ, [
        [W//2]*suplen + [1] + [0]*msglen
    ] + [
        [ pow(s, j+1, W) for s in Support ] + [0] + [0]*j + [1] + [0]*(msglen -1 -j)
        for j in range(msglen)
    ] + [
        [0]*i + [W] + [0]*(suplen -1 -i)    + [0]*(1 + msglen)
        for i in range(suplen)
    ])

bound = [256 - wi for wi in w]
D = matrix.diagonal(QQ, [2**20/QQ(b) for b in bound] + [2**30] + [1]*msglen).dense_matrix()

print('LLL...')
L = (M*D).LLL()/D
print('LLL!')

display = lambda x: ' '.join(f'{y:>3}' for y in x)

for row in L:
    if abs(row[suplen]) == 1:
        print('-'*50)
        msg = row[suplen+1:]
        print('msg:', msg)
        print('enc:', display(enc := _encoding(list( msg ))),       f'[{sum(enc):>4}]')
        print('enc:', display(enc := _encoding(list(-msg ))),       f'[{sum(enc):>4}]')
        print('enc:', display(enc := _encoding(list( msg[::-1] ))), f'[{sum(enc):>4}]')
        print('enc:', display(enc := _encoding(list(-msg[::-1] ))), f'[{sum(enc):>4}]')
        print('max:', display(bound), f'[{sum(bound):>4}]')


io.close()