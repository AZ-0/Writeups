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

from tqdm import trange

for phase in range(4):
    end_phase = (phase + 50) % 4
    partp = partial(p, phase)
    realc = partial(c, end_phase)

    print(f'Bruting partial key relations (phase {phase})')
    for partk in trange(2**32):
        partk  = [partk & 0xFF, (partk >> 8) & 0xFF, (partk >> 16) & 0xFF, (partk >> 24) & 0xFF]
        partrk = partial_expand(partk, phase)
        partc, _ = partial_encrypt(partp, partrk, phase)
        if partc == realc:
            print('DING DING DING!!!')
            print('partk =', partk)
            with open('partk.txt', 'a') as file:
                file.write(f'phase{phase} = {partrk}')
            break
    else:
        print('THIS. IS. A BUG! >:c')

print('DONE!')