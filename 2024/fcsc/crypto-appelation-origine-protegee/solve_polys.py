from sage.all import *

p = 18446744073709551557 # p-1 not a multiple of 3
# R = PolynomialRing(GF(p), 'r2,r3,r4,r5,x4', sparse=True)
# gens = r2,r3,r4,r5,x4 = R.gens()

cf  = lambda f, m: f.monomial_coefficient(m)

exec(rf"""
r5 = PolynomialRing(GF(p), 'x', sparse=False).gen()
print('Exploding...')

print('1...')
d = 3**4
r4 = ((r5)**d - (13988780922563076591*r5 + 16000332491415074610))/7378697629483820623

print('2...')
d = 3**3
r3 = ((r4)**d - (7778377084414194236*r4 + 2503120688890865465*r5 + 13423691880508614669))/7378697629483820623

print('3...')
d = 3**2
r2 = ((r3)**d - (7778377084414194236*r3 + 2772648116190066165*r4 + 9362106924575798838*r5 + 14444317458727592310))/7378697629483820623 

print('4...')
d = 3**1
r1 = ((r2)**d - (7778377084414194236*r2 + 2772648116190066165*r3 + 10226900534942455032*r4 + 11788916308420680736*r5 + 5160591037004176468))/7378697629483820623

print('5...')
d = 3**0
eq = (r1)**d - (7778377084414194236*r1 + 2772648116190066165*r2 + 10226900534942455032*r3 + 5236236265375862780*r4 + 1051894753200383697*r5 + 4096908300467309361)

print('Saving...')
with open('eq.txt', 'w') as file:
    file.write(str(eq))

print('Solving...')
r = eq.any_root()

print('r5 =', r)
with open('root.txt', 'w') as file:
    file.write('x4 = ')
    file.write(str(r))
""")
