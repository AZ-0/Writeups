# __| 0  1  2  3  t
# … |       
# … |       …
# … |    …  !
# x | …  !  .
# y | !  *  .     …
# z | *  *  .     !
# u | *  *  .     *   # a^b^c^d; a^d; a^b; c
# v | ^  ^  ^     ^
#
#  !: deduced from inverse table 2), and then after.
#  dérivation suspecte (problème de théorie de l'information ?)
#  à implem pour tester

from tight_schedule import os, TightSchedule as TS
S = TS.S
RCON = TS.RCON

#            a           b           c           d     
#  k p | 0 1 2 3 t | 0 1 2 3 t | 0 1 2 3 t | 0 1 2 3 t |
# ──────────────────────────────────────────────────────
#  0 0 |       .   |     ^ ^   |   ^   ^   | ^ ^ ^ ^   | ← k0
#  1 1 |     ^ ^ b |   ^   ^   | ^ ^ ^ ^   |       . @ | ← k1
#  2 2 |   ^   ^   | ^ ^ ^ ^   |       . @ |     ^ ^ b | ← k2
#  3 3 | ^ ^ ^ ^   |       . @ |     ^ ^ b |           |
#  4 0 |       * @ |     ^ ^ b |   ^   ^   |           |
#  5 1 |     ^ ^ b |   ^   ^   | ^ ^ ^ ^   |       * @ | ← round 5 of p+k0
#  6 2 |           |           |       * @ |         b |
#  7 3 |           |       * @ |         b |           |
#  8 0 |       * @ |     ^ ^ b |           |           |
#  9 1 |     ^ ^ b |   ^   ^   |           |       * @ |
# 10 2 |   ^   ^   | ^ ^ ^ ^   |       * @ |     ^ ^ b | ← round 5 of p+k1

def xor(x, y):
    return [x^y for x,y in zip(x, y)]

def blocks(x, n=4):
    return [x[i:i+n] for i in range(0, len(x), n)]

def partial(k, phase):
    bk = blocks(k)
    a, b, c, d = 0, 1, 2, 3 # for readability

    if phase == 0:
        return [
            bk[3][a],
            bk[2][b] ^ bk[3][b],
            bk[1][c] ^ bk[3][c],
            bk[0][d] ^ bk[1][d] ^ bk[2][d] ^ bk[3][d],
        ]

    if phase == 1:
        return [
            bk[2][a] ^ bk[3][a],
            bk[1][b] ^ bk[3][b],
            bk[0][c] ^ bk[1][c] ^ bk[2][c] ^ bk[3][c],
            bk[3][d],
        ]

    if phase == 2:
        return [
            bk[1][a] ^ bk[3][a],
            bk[0][b] ^ bk[1][b] ^ bk[2][b] ^ bk[3][b],
            bk[3][c],
            bk[2][d] ^ bk[3][d],
        ]

    if phase == 3:
        return [
            bk[0][a] ^ bk[1][a] ^ bk[2][a] ^ bk[3][a],
            bk[3][b],
            bk[2][c] ^ bk[3][c],
            bk[1][d] ^ bk[3][d],
        ]

    raise ValueError('phase should be one of 0,1,2,3')

def partial_round(partx, phase, cst=0):
    a, b, c, d = partx
    if phase == 0:
        return [a, b, c, d ^ S[a]]
    if phase == 1:
        return [a, b, c ^ S[d], d]
    if phase == 2:
        return [a, b ^ S[c], c, d]
    if phase == 3:
        return [a ^ S[b] ^ cst, b, c, d]
    raise ValueError('phase should be one of 0,1,2,3')

def partial_expand(partk, phase):
    partrk = [partk]
    for _ in range(10):
        partrk.append(partial_round(partrk[-1], phase, RCON[len(partrk)]))
        phase = (phase + 1) % 4
    return partrk

def partial_encrypt(partp, partrk, phase):
    c = partp
    for sk in partrk[:-1]:
        c = xor(c, sk)
        for _ in range(5):
            c = partial_round(c, phase)
            phase = (phase + 1) % 4
    return xor(c, partrk[-1]), phase

k = os.urandom(16)
p = os.urandom(16)
P = TS(k)
c = P.encrypt(p)

partk  = partial(k, 0)
partrk = partial_expand(partk, 0)
partp  = partial(p, 0)
partc, phase = partial_encrypt(partp, partrk, 0)

for i, (sk, partsk) in enumerate(zip(P.rk, partrk)):
    assert partsk == partial(sk, i%4), f'failed #{i}'

assert partc == partial(c, phase)
print('Assertions passed!')

p = bytes.fromhex("0dfa4c6052fb87ef0a8f03f705dd5101")
c = bytes.fromhex("d4ed19e0694101b6b151e11c2db973bf")
iv = bytes.fromhex("cd31cb6e6ded184efbb9a398e31ffdbb")
flag_enc = bytes.fromhex("653ec0cdd7e3a98c33414be8ef07c583d87b876afbff1d960f8f43b5a338e9ff96d87da4406ebe39a439dab3a84697d40c24557cd1ea6f433053451d20ce1fbf191270f4b8cc7891f8779eb615d35c9f")

# Bruting phased key (phase 0)
# a = 0 | a = 1 | a = 2 | a = 3 | a = 4 | a = 5 | a = 6 | a = 7 | a = 8 | a = 9 | a = 10 | a = 11 | a = 12 | a = 13 | a = 14 | a = 15 | a = 16 | a = 17 | a = 18 | a = 19 | a = 20 | a = 21 | a = 22 | a = 23 | a = 24 | a = 25 | a = 26 | a = 27 | a = 28 | a = 29 | a = 30 | a = 31 | a = 32 | a = 33 | a = 34 | a = 35 | a = 36 | a = 37 | a = 38 | a = 39 | a = 40 | a = 41 | a = 42 | a = 43 | a = 44 | a = 45 | a = 46 | a = 47 | a = 48 | a = 49 | a = 50 | a = 51 | a = 52 | a = 53 | a = 54 | a = 55 | a = 56 | a = 57 | a = 58 | a = 59 | a = 60 | a = 61 | a = 62 | a = 63 | a = 64 | a = 65 | a = 66 | a = 67 | a = 68 | a = 69 | a = 70 | a = 71 | a = 72 | a = 73 | a = 74 | a = 75 | a = 76 | DING DING DING!!!
# partk = [76, 127, 191, 108]
# Bruting phased key (phase 1)
# a = 0 | a = 1 | a = 2 | a = 3 | a = 4 | a = 5 | a = 6 | a = 7 | a = 8 | a = 9 | a = 10 | a = 11 | a = 12 | a = 13 | a = 14 | a = 15 | a = 16 | a = 17 | a = 18 | a = 19 | a = 20 | a = 21 | a = 22 | a = 23 | a = 24 | a = 25 | a = 26 | a = 27 | a = 28 | a = 29 | a = 30 | a = 31 | a = 32 | a = 33 | a = 34 | a = 35 | a = 36 | a = 37 | a = 38 | a = 39 | a = 40 | a = 41 | a = 42 | a = 43 | a = 44 | a = 45 | a = 46 | a = 47 | a = 48 | a = 49 | a = 50 | a = 51 | a = 52 | a = 53 | a = 54 | a = 55 | a = 56 | a = 57 | a = 58 | a = 59 | a = 60 | a = 61 | a = 62 | a = 63 | a = 64 | a = 65 | a = 66 | a = 67 | a = 68 | a = 69 | a = 70 | a = 71 | DING DING DING!!!
# partk = [71, 142, 75, 90]
# Bruting phased key (phase 2)
# a = 0 | a = 1 | a = 2 | a = 3 | a = 4 | a = 5 | a = 6 | a = 7 | a = 8 | a = 9 | a = 10 | a = 11 | a = 12 | a = 13 | a = 14 | a = 15 | a = 16 | a = 17 | a = 18 | a = 19 | a = 20 | a = 21 | a = 22 | a = 23 | a = 24 | a = 25 | a = 26 | a = 27 | a = 28 | a = 29 | a = 30 | a = 31 | a = 32 | a = 33 | a = 34 | a = 35 | a = 36 | a = 37 | a = 38 | a = 39 | a = 40 | a = 41 | a = 42 | a = 43 | a = 44 | a = 45 | a = 46 | a = 47 | a = 48 | a = 49 | a = 50 | a = 51 | a = 52 | a = 53 | a = 54 | a = 55 | a = 56 | a = 57 | a = 58 | a = 59 | a = 60 | a = 61 | a = 62 | a = 63 | a = 64 | a = 65 | a = 66 | a = 67 | a = 68 | a = 69 | a = 70 | a = 71 | a = 72 | a = 73 | a = 74 | a = 75 | a = 76 | a = 77 | a = 78 | a = 79 | a = 80 | a = 81 | a = 82 | a = 83 | a = 84 | a = 85 | a = 86 | a = 87 | a = 88 | a = 89 | a = 90 | a = 91 | a = 92 | a = 93 | a = 94 | a = 95 | a = 96 | DING DING DING!!!
# partk = [96, 185, 153, 233]
# Bruting phased key (phase 3)
# a = 0 | a = 1 | a = 2 | a = 3 | a = 4 | a = 5 | a = 6 | a = 7 | DING DING DING!!!
# partk = [7, 64, 187, 9]
# Segmentation fault

partks = [
    [76, 127, 191, 108],
    [71, 142, 75, 90],
    [96, 185, 153, 233],
    [7, 64, 187, 9]
]

for phase in range(4):
    end_phase = (phase + 50) % 4
    partp = partial(p, phase)
    realc = partial(c, end_phase)

    partk = partks[phase]
    partrk = partial_expand(partk, phase)
    partc, _ = partial_encrypt(partp, partrk, phase)
    if partc == realc:
        print('DING DING DING!!!')
    else:
        print('NOOOOOOOOOO')

#            a           b           c           d     
#  k p | 0 1 2 3 t | 0 1 2 3 t | 0 1 2 3 t | 0 1 2 3 t |
# ──────────────────────────────────────────────────────
#  0 0 |       .   |     ^ ^   |   ^   ^   | ^ ^ ^ ^   | ← k0
#  1 1 |     ^ ^ b |   ^   ^   | ^ ^ ^ ^   |       . @ | ← k1
#  2 2 |   ^   ^   | ^ ^ ^ ^   |       . @ |     ^ ^ b | ← k2
#  3 3 | ^ ^ ^ ^   |       . @ |     ^ ^ b |   ^   ^   |
#  4 0 |       * @ |     ^ ^ b |   ^   ^   | ^ ^ ^ ^   |
#  5 1 |     ^ ^ b |   ^   ^   | ^ ^ ^ ^   |       * @ | ← round 5 of p+k0
#  6 2 |           |           |       * @ |         b |
#  7 3 |           |       * @ |         b |           |
#  8 0 |       * @ |     ^ ^ b |           |           |
#  9 1 |     ^ ^ b |   ^   ^   |           |       * @ |
# 10 2 |   ^   ^   | ^ ^ ^ ^   |       * @ |     ^ ^ b | ← round 5 of p+k1

pk0, pk1, pk2, pk3 = partks

a, b, c, d = 0, 1, 2, 3
k = [None]*16

k[3*4+a] = pk0[a]
k[3*4+b] = pk3[b]
k[3*4+c] = pk2[c]
k[3*4+d] = pk1[d]

k[2*4+a] = pk0[a] ^ pk1[a]
k[2*4+b] = pk3[b] ^ pk0[b]
k[2*4+c] = pk2[c] ^ pk3[c]
k[2*4+d] = pk1[d] ^ pk2[d]

k[1*4+a] = pk0[a] ^ pk2[a]
k[1*4+b] = pk3[b] ^ pk1[b]
k[1*4+c] = pk2[c] ^ pk0[c]
k[1*4+d] = pk1[d] ^ pk3[d]

k[0*4+a] = pk0[a] ^ pk1[a] ^ pk2[a] ^ pk3[a]
k[0*4+b] = pk0[b] ^ pk1[b] ^ pk2[b] ^ pk3[b]
k[0*4+c] = pk0[c] ^ pk1[c] ^ pk2[c] ^ pk3[c]
k[0*4+d] = pk0[d] ^ pk1[d] ^ pk2[d] ^ pk3[d]

k = bytes(k)

p = bytes.fromhex("0dfa4c6052fb87ef0a8f03f705dd5101")
c = bytes.fromhex("d4ed19e0694101b6b151e11c2db973bf")
iv = bytes.fromhex("cd31cb6e6ded184efbb9a398e31ffdbb")
flag_enc = bytes.fromhex("653ec0cdd7e3a98c33414be8ef07c583d87b876afbff1d960f8f43b5a338e9ff96d87da4406ebe39a439dab3a84697d40c24557cd1ea6f433053451d20ce1fbf191270f4b8cc7891f8779eb615d35c9f")

assert TS(k).encrypt(p) == c

from Crypto.Cipher import AES
E = AES.new(k, AES.MODE_CBC, iv = iv)
flag = E.decrypt(flag_enc)
print(flag)