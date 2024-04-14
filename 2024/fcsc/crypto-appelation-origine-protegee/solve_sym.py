from sage.all import *
from hashlib import sha256
from pprint import pprint

p = 18446744073709551557 # p-1 not a multiple of 3
t = 5
r = 9
RC = [
    [ int.from_bytes(sha256(b"FCSC2024#" + str(t*j + i).encode()).digest()) % p for i in range(t) ]
    for j in range(r)
]
M = [
    [ pow(i, j, p) for i in range(1, t + 1) ]
    for j in range(t)
]

R = PolynomialRing(GF(p), 'x1,x2,x3,x4,r1,r2,r3,r4,r5,r6,r7,r8')
xs = R.gens()[:4]
rs = R.gens()[4:]
symX = [0, *xs]

RC = [vector(R, rc) for rc in RC]
M = matrix(R, M)
N = M.inverse()


class SymAOP:
    def __init__(self):
        self.rels = []

    def R(self, r):
        # self.S <- self.S * M   # S = [ S(i) for 0 < i < t+1 ] où S est considéré comme un polynôme
        self.S = self.S * M

        # self.S <- self.S + RC[r]
        self.S += RC[r]

        # self.S <- self.S ** e
        if r < 8:
            self.rels.append(self.S[0] - rs[r]**(3**9)) # WRONG EQUATION !!!! Should be S[0]^(3^9) = rs[r]
            self.S[0] = rs[r]
        else:
            self.rels.append(self.S[0])

    def __call__(self, L):
        assert len(L) == t, f"Error: input must be a list of {t} elements."
        self.S = vector(R, L)
        for i in range(r):
            print('> round', i)
            self.R(i)
        return self.S


symaop = SymAOP()
symY = symaop(symX)

print(f'\n---- symY: {len(symY)}\n')
for yi in symY:
    print(yi, end='\n\n')

print(f'\n---- rels: {len(symaop.rels)}\n')
for ri in symaop.rels:
    print(ri, end='\n\n')


print(f'\n---- unks: {R.ngens()}\n')


rels = symaop.rels[:]

rel  = rels.pop()
x1   = -rel(x1=0)/rel.coefficient(xs[0])
rels = [ rel(x1=x1) for rel in rels ]

rel  = rels.pop()
x2   = -rel(x2=0)/rel.coefficient(xs[1])
rels = [ rel(x2=x2) for rel in rels ]

rel  = rels.pop()
x3   = -rel(x3=0)/rel.coefficient(xs[2])
rels = [ rel(x3=x3) for rel in rels ]

rel  = rels.pop()
x4   = -rel(x4=0)/rel.coefficient(xs[3])
rels = [ rel(x4=x4) for rel in rels ]

rels = [ rel(r8 = 0, r7 = 0, r6 = 0) for rel in rels ]

rel  = rels.pop(0)
r5   = -rel(r5=0)/rel.coefficient(rs[4])
rels = [ rel(r5=r5) for rel in rels ]

# rel  = rels.pop()
# x1   = -rel(x1=0)/rel.coefficient(xs[0])
# rels = [ rel(x1=x1) for rel in rels ]

# rel  = rels.pop()
# x2   = -rel(x2=0)/rel.coefficient(xs[1])
# rels = [ rel(x2=x2) for rel in rels ]

print('DONE')

# print(f'\n---- rels: {len(rels)}\n')
# for ri in rels:
#     print(ri, end='\n\n')

# print('Grobner...')
# R = PolynomialRing(GF(p), 5, 'r1,r2,r3,r4,r5', order='lex')
# rels = [
#     R({ k[4:9] : v for k, v in rel.dict().items() })
#     for rel in rels
# ]

# I = Ideal(rels)
# B = I.groebner_basis()
# print(f'\n---- base: {len(B)}\n')
# for b in B:
#     print(b, end='\n\n')

exit()


def inv_round(S, r):
    # S <- S ** (1/e)
    e = pow(3, -r, p-1)
    d = pow(3, r, p-1)
    s = pow(S[0], d, p)
    assert pow(s, e, p) == S[0]
    S[0] = s

    # S <- S - RC[r]
    for j in range(t):
        S[j] -= RC[r][j]

    # S <- S * M   # S = [ S(i) for 0 < i < t+1 ] où S est considéré comme un polynôme
    s = [ 0 ] * t
    for j in range(t):
        for i in range(t):
            s[j] += N[i][j] * S[i]
        s[j] = int(s[j])
    return s


def inv_aop(L):
    assert len(L) == t, f"Error: input must be a list of {t} elements."
    # assert all(x in range(0, self.p) for x in L), f"Error: elements must be in [0..{self.p - 1}]."
    S = L[:]
    for i in range(r-1, -1, -1):
        S = inv_round(S, i)
    return S



if __name__ ==  "__main__":
    Y = [1, 2, 3, 4, 5]
    X = inv_aop(Y)

    aop = AOP()

    X = [ int(x) for x in X ]
    Y = aop(X)
    if X[0] == 0 and Y[0] == 0:
        print('it works lol')
    else:
        print('ohno')
        print('X =', X)
        print('Y =', [y%p for y in Y])
