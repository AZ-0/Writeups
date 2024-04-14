from sage.all import *
from hashlib import sha256

# ------------------ SETUP ------------------ #

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

R = PolynomialRing(GF(p), 'x1,x2,x3,x4,r1,r2,r3,r4,r5,r6,r7,r8,r9')
gens = R.gens()
xs = gens[:-9]
rs = gens[-9:]
symX = [0, *xs]

RC = [vector(R, rc) for rc in RC]
M = matrix(GF(p), M)
N = M.inverse()

# ------------------------------------------- #

class SymAOP:
    def __init__(self):
        self.p = 18446744073709551557 # p - 1 not a multiple of 3
        self.t = 5
        self.r = 9
        self.RC = [
            [ int.from_bytes(sha256(b"FCSC2024#" + str(self.t*j + i).encode()).digest()) % self.p for i in range(self.t) ]
            for j in range(self.r)
        ]
        self.M = [
            [ pow(i, j, self.p) for i in range(1, self.t + 1) ]
            for j in range(self.t)
        ]

        self.rels = []

    def R(self, r):
        s = [ 0 ] * t
        for j in range(self.t):
            for i in range(self.t):
                s[j] += self.M[i][j] * self.S[i]
            s[j] %= self.p
        self.S = s[:]

        # self.S <- self.S + RC[i]
        for j in range(self.t):
            self.S[j] += self.RC[r][j]

        # S <- S ** e ;  e = 3^-r ;  d = 3^r
        d = pow(3, r, p - 1)
        self.rels.append([ d, self.S[0], rs[r] ])
        self.S[0] = rs[r]

    # def dec(self, L, start=r, end=0):
    #     assert len(L) == t, f"Error: input must be a list of {t} elements."
    #     S = vector(R, L)
    #     for i in range(start-1, end-1, -1):
    #         print('> round', i)
    #         S = self.invR(i, S)

    #     if end == 0:
    #         self.rels.append([ S[0], R(0) ])
    #     return S

    def enc(self, L, start=0, end=r):
        assert len(L) == t, f"Error: input must be a list of {t} elements."
        self.S = vector(R, L)
        for i in range(start, end):
            print('> round', i)
            self.R(i)
        return self.S

# ------------------------------------------- #

x1, x2, x3, x4 = xs
r1, r2, r3, r4, r5, r6, r7, r8, r9 = rs

symaop = SymAOP()
symY = symaop.enc(symX)
rels = [ *symaop.rels ]

# Linear var change to get rid of xi
X1 = (x1 - (8956834208064*x2 + 43492623605344*x3 + 212599312843008*x4 + 575671200*r1 + 845900*r2 + 1270*r3 + 4*r4 + r5 + 2136202046718859877))/1861530726784
X2 = (x2 - (5432016942665893572*x1 + 3791239690578314005*x3 + 15091824996494267841*x4 + 3484612212443219510*r1 + 11689751454529104201*r2 + 420766381688291778*r3 + 15165420376755530096*r4 + 13014727131043657989*r5 + r6 + 17111796702991654756))/15707416284860911339
X3 = (x3 - (4237673785012171002*x1 + 15875638347443638650*x2 + 10699464035458974743*x4 + 7825423946558485226*r1 + 684310003160703926*r2 + 13364376464197462747*r3 + 1726620244780479750*r4 + 6046749120051481896*r5 + 2571105726265912911*r6 + r7 + 2708169302857896252))/9991921872496112048
X4 = (x4 - (13771876016190994156*x1 + 11565924911902171271*x2 + 9241227989834677356*x3 + 12768132314702093820*r1 + 1190222494928938651*r2 + 13003811092926216758*r3 + 17115887457073743939*r4 + 9521084420273921020*r5 + 6809395349887775246*r6 + 9205516083874874205*r7 + r8 + 5193023854195183586))/5258946514700722596

rels = [
    [
        d,
        ri(x1=X1)(x2=X2)(x3=X3)(x4=X4),
        zi(x1=X1)(x2=X2)(x3=X3)(x4=X4)
    ]
    for d, ri, zi in rels
]

print(f'\n---- unks: {R.ngens()}\n')
print(gens, end='\n\n')

print(f'\n---- rels: {len(rels)}\n')
for d, ri, zi in rels:
    print(f'{zi}^{d} = {ri}', end='\n\n')


# R6 = R(randint(1, p))
# R7 = R(randint(1, p))
# R8 = R(randint(1, p))
R6 = R(3669358667589448394) # random values for which there is a root
R7 = R(1596967123920739849)
R8 = R(1489437672216361050)
R9 = R(0)
X1 = R6**(3**5)
X2 = R7**(3**6)
X3 = R8**(3**7)
X4 = R9**(3**8)

print('-'*50)
print('r6 =', R6)
print('r7 =', R7)
print('r8 =', R8)
print('r9 =', R9)

polys = [
    zi(r6=R6,r7=R7,r8=R8,r9=R9, x1=X1,x2=X2,x3=X3,x4=X4)**d -
    ri(r6=R6,r7=R7,r8=R8,r9=R9, x1=X1,x2=X2,x3=X3,x4=X4)
    for d, ri, zi in rels
]
polys = [ f for f in polys if f != 0 ]
assert not any(f.is_constant() for f in polys)
assert len(polys) == 5

assert polys[4].degree(r5) == 3**4 and polys[4].degree(r4) == 1 and polys[4].degree(r3) == 0 and polys[4].degree(r2) == 0 and polys[4].degree(r1) == 0
assert polys[3].degree(r4) == 3**3 and polys[3].degree(r3) == 1 and polys[3].degree(r2) == 0 and polys[3].degree(r1) == 0
assert polys[2].degree(r3) == 3**2 and polys[2].degree(r2) == 1 and polys[2].degree(r1) == 0
assert polys[1].degree(r2) == 3**1 and polys[1].degree(r1) == 1

exec(rf"""
r5 = PolynomialRing(GF(p), 'x', sparse=False).gen()
print('Exploding...')

print('1...')
r4 = {str(r4 - polys[4]/polys[4].monomial_coefficient(r4)).replace('^', '**')}

print('2...')
r3 = {str(r3 - polys[3]/polys[3].monomial_coefficient(r3)).replace('^', '**')}

print('3...')
r2 = {str(r2 - polys[2]/polys[2].monomial_coefficient(r2)).replace('^', '**')}

print('4...')
r1 = {str(r1 - polys[1]/polys[1].monomial_coefficient(r1)).replace('^', '**')}

print('5...')
eq = {polys[0]}
""")
print('Solving...')
r5 = eq.any_root()

print('r5 =', r)
with open('root.txt', 'w') as file:
    file.write('r5 = ')
    file.write(str(r))

r1 = r1(r5)
r2 = r2(r5)
r3 = r3(r5)
r4 = r4(r5)
print('polys:', [poly(r1=r1,r2=r2,r3=r3,r4=r4,r5=r5) % p for poly in polys])

print('r1 =', r1)
print('r2 =', r2)
print('r3 =', r3)
print('r4 =', r4)

r6, r7, r8, r9 = R6, R7, R8, R9
x1, x2, x3, x4 = X1, X2, X3, X4

print('rels:', [
    zi(r1=r1,r2=r2,r3=r3,r4=r4,r5=r5,r6=r6,r7=r7,r8=r8,r9=r9, x1=X1,x2=X2,x3=X3,x4=X4)**d -
    ri(r1=r1,r2=r2,r3=r3,r4=r4,r5=r5,r6=r6,r7=r7,r8=r8,r9=r9, x1=X1,x2=X2,x3=X3,x4=X4)
    for d, ri, zi in rels
])

x4 = (x4 - (13771876016190994156*x1 + 11565924911902171271*x2 + 9241227989834677356*x3 + 12768132314702093820*r1 + 1190222494928938651*r2 + 13003811092926216758*r3 + 17115887457073743939*r4 + 9521084420273921020*r5 + 6809395349887775246*r6 + 9205516083874874205*r7 + r8 + 5193023854195183586))/5258946514700722596
x3 = (x3 - (4237673785012171002*x1 + 15875638347443638650*x2 + 10699464035458974743*x4 + 7825423946558485226*r1 + 684310003160703926*r2 + 13364376464197462747*r3 + 1726620244780479750*r4 + 6046749120051481896*r5 + 2571105726265912911*r6 + r7 + 2708169302857896252))/9991921872496112048
x2 = (x2 - (5432016942665893572*x1 + 3791239690578314005*x3 + 15091824996494267841*x4 + 3484612212443219510*r1 + 11689751454529104201*r2 + 420766381688291778*r3 + 15165420376755530096*r4 + 13014727131043657989*r5 + r6 + 17111796702991654756))/15707416284860911339
x1 = (x1 - (8956834208064*x2 + 43492623605344*x3 + 212599312843008*x4 + 575671200*r1 + 845900*r2 + 1270*r3 + 4*r4 + r5 + 2136202046718859877))/1861530726784


print('rels:', [
    zi(r1=r1,r2=r2,r3=r3,r4=r4,r5=r5,r6=r6,r7=r7,r8=r8,r9=r9, x1=x1,x2=x2,x3=x3,x4=x4)**d -
    ri(r1=r1,r2=r2,r3=r3,r4=r4,r5=r5,r6=r6,r7=r7,r8=r8,r9=r9, x1=x1,x2=x2,x3=x3,x4=x4)
    for d, ri, zi in symaop.rels
])

print('x1 =', x1)
print('x2 =', x2)
print('x3 =', x3)
print('x4 =', x4)
print(', '.join(map(str, [0, x1, x2, x3, x4])))
