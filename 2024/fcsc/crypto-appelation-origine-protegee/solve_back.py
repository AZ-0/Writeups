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

R = PolynomialRing(GF(p), 'x1,x2,x3,x4,r1,r2,r3,r4,r5,r6,r7,r8')
gens = R.gens()
xs = gens[:-8]
rs = gens[-8:]
symX = [0, *xs]

RC = [vector(R, rc) for rc in RC]
M = matrix(GF(p), M)
N = M.inverse()

# ------------------------------------------- #

class SymAOP:
    def __init__(self):
        self.rels = []

    def invR(self, r, S):
        # S <- S ** 1/e
        if S[0] != 0:
            self.rels.append([ rs[r], S[0] ])
            S[0] = rs[r]

        # S <- S - RC[r]
        S -= RC[r]

        # S <- S / M   # S = [ S(i) for 0 < i < t+1 ] où S est considéré comme un polynôme
        S = S * N

        return S

    def R(self, r, S):
        # S <- S * M   # S = [ S(i) for 0 < i < t+1 ] où S est considéré comme un polynôme
        S = S * M

        # S <- S + RC[r]
        S += RC[r]

        # S <- S ** e ;  e = 3^-r ;  d = 3^r
        if r < 8:
            self.rels.append([ S[0], rs[r] ])
            S[0] = rs[r]
        else:
            self.rels.append([ S[0], R(0) ])
        
        return S

    def dec(self, L, start=r, end=0):
        assert len(L) == t, f"Error: input must be a list of {t} elements."
        S = vector(R, L)
        for i in range(start-1, end-1, -1):
            print('> round', i)
            S = self.invR(i, S)

        if end == 0:
            self.rels.append([ S[0], R(0) ])
        return S

    def enc(self, L, start=0, end=r):
        assert len(L) == t, f"Error: input must be a list of {t} elements."
        S = vector(R, L)
        for i in range(start, end):
            print('> round', i)
            S = self.R(i, S)
        return S

# ------------------------------------------- #

x1, x2, x3, x4 = xs
r1, r2, r3, r4, r5, r6, r7, r8 = rs

symaop = SymAOP()
symY = symaop.enc(symX)
rels = [ *symaop.rels ]

X1 = (x1 - (8956834208064*x2 + 43492623605344*x3 + 212599312843008*x4 + 575671200*r1 + 845900*r2 + 1270*r3 + 4*r4 + r5 + 2136202046718859877))/1861530726784
X2 = (x2 - (5432016942665893572*x1 + 3791239690578314005*x3 + 15091824996494267841*x4 + 3484612212443219510*r1 + 11689751454529104201*r2 + 420766381688291778*r3 + 15165420376755530096*r4 + 13014727131043657989*r5 + r6 + 17111796702991654756))/15707416284860911339
X3 = (x3 - (4237673785012171002*x1 + 15875638347443638650*x2 + 10699464035458974743*x4 + 7825423946558485226*r1 + 684310003160703926*r2 + 13364376464197462747*r3 + 1726620244780479750*r4 + 6046749120051481896*r5 + 2571105726265912911*r6 + r7 + 2708169302857896252))/9991921872496112048
X4 = (x4 - (13771876016190994156*x1 + 11565924911902171271*x2 + 9241227989834677356*x3 + 12768132314702093820*r1 + 1190222494928938651*r2 + 13003811092926216758*r3 + 17115887457073743939*r4 + 9521084420273921020*r5 + 6809395349887775246*r6 + 9205516083874874205*r7 + r8 + 5193023854195183586))/5258946514700722596

rels = [
    [
        ri(x1=X1)(x2=X2)(x3=X3)(x4=X4),
        zi(x1=X1)(x2=X2)(x3=X3)(x4=X4)
    ]
    for ri, zi in rels
]


R6 = 3599823432592753648
R7 = 18189693054119072609
R8 = 6190922203467627100
X1 = R6**(3**5)
X2 = R7**(3**6)
X3 = R8**(3**7)
X4 = R(0)

polys = [
    ri(r6=R6,r7=R7,r8=R8, x1=X1,x2=X2,x3=X3,x4=X4)
    for ri, zi in rels
    if not zi.is_constant()
]

r5 = GF(p)(17803589413948442552)

exec(rf"""
print('Exploding...')

print('1...')
d = 3**4
r4 = ((r5)**d - (13988780922563076591*r5 + {polys[4].constant_coefficient()}))/7378697629483820623

print('2...')
d = 3**3
r3 = ((r4)**d - (7778377084414194236*r4 + 2503120688890865465*r5 + {polys[3].constant_coefficient()}))/7378697629483820623

print('3...')
d = 3**2
r2 = ((r3)**d - (7778377084414194236*r3 + 2772648116190066165*r4 + 9362106924575798838*r5 + {polys[2].constant_coefficient()}))/7378697629483820623 

print('4...')
d = 3**1
r1 = ((r2)**d - (7778377084414194236*r2 + 2772648116190066165*r3 + 10226900534942455032*r4 + 11788916308420680736*r5 + {polys[1].constant_coefficient()}))/7378697629483820623
""")

r6, r7, r8 = R6, R7, R8
x1, x2, x3, x4 = X1, X2, X3, X4

x4 = x4*5258946514700722596 + (13771876016190994156*x1 + 11565924911902171271*x2 + 9241227989834677356*x3 + 12768132314702093820*r1 + 1190222494928938651*r2 + 13003811092926216758*r3 + 17115887457073743939*r4 + 9521084420273921020*r5 + 6809395349887775246*r6 + 9205516083874874205*r7 + r8 + 5193023854195183586)
x3 = x3*9991921872496112048 + (4237673785012171002*x1 + 15875638347443638650*x2 + 10699464035458974743*x4 + 7825423946558485226*r1 + 684310003160703926*r2 + 13364376464197462747*r3 + 1726620244780479750*r4 + 6046749120051481896*r5 + 2571105726265912911*r6 + r7 + 2708169302857896252)
x2 = x2*15707416284860911339 + (5432016942665893572*x1 + 3791239690578314005*x3 + 15091824996494267841*x4 + 3484612212443219510*r1 + 11689751454529104201*r2 + 420766381688291778*r3 + 15165420376755530096*r4 + 13014727131043657989*r5 + r6 + 17111796702991654756)
x1 = x1*1861530726784 + (8956834208064*x2 + 43492623605344*x3 + 212599312843008*x4 + 575671200*r1 + 845900*r2 + 1270*r3 + 4*r4 + r5 + 2136202046718859877)

_x1, _x2, _x3, _x4 = x1, x2, x3, x4
_x1 = (_x1 - (8956834208064*_x2 + 43492623605344*_x3 + 212599312843008*_x4 + 575671200*r1 + 845900*r2 + 1270*r3 + 4*r4 + r5 + 2136202046718859877))/1861530726784
_x2 = (_x2 - (5432016942665893572*_x1 + 3791239690578314005*_x3 + 15091824996494267841*_x4 + 3484612212443219510*r1 + 11689751454529104201*r2 + 420766381688291778*r3 + 15165420376755530096*r4 + 13014727131043657989*r5 + r6 + 17111796702991654756))/15707416284860911339
_x3 = (_x3 - (4237673785012171002*_x1 + 15875638347443638650*_x2 + 10699464035458974743*_x4 + 7825423946558485226*r1 + 684310003160703926*r2 + 13364376464197462747*r3 + 1726620244780479750*r4 + 6046749120051481896*r5 + 2571105726265912911*r6 + r7 + 2708169302857896252))/9991921872496112048
_x4 = (_x4 - (13771876016190994156*_x1 + 11565924911902171271*_x2 + 9241227989834677356*_x3 + 12768132314702093820*r1 + 1190222494928938651*r2 + 13003811092926216758*r3 + 17115887457073743939*r4 + 9521084420273921020*r5 + 6809395349887775246*r6 + 9205516083874874205*r7 + r8 + 5193023854195183586))/5258946514700722596
assert _x1 == X1
assert _x2 == X2
assert _x3 == X3
assert _x4 == X4

print('x1 =', x1)
print('x2 =', x2)
print('x3 =', x3)
print('x4 =', x4)
print([0, x1, x2, x3, x4])