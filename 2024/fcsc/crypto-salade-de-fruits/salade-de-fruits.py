from itertools import count
from hashlib import sha256

for x in count(start = 1):
  for y in range(1, x + 1):
    for z in range(1, x + 1):
      if x ** 3 + y ** 3 == 94 * z ** 3:
        h = sha256(str(z).encode()).hexdigest()
        print(f"FCSC{{{h}}}")
        exit(1)


### sage

x,y,z = polygens(QQ, 'x,y,z')
phi = EllipticCurve_from_cubic(x**3 + y**3 - 94 * z**3)
E = phi.codomain()
P, = E.gens()
psi = phi.inverse()
Q = psi(P); Q.clear_denominators(); Q
X,Y,Z = list(Q)
assert X^3 + Y^3 == 94*Z^3

### magma

P2<X,Y,Z> := ProjectiveSpace(RationalField(), 2);
C := Curve(P2, X^3 + Y^3 - 94*Z^3);
E, phi := EllipticCurve(C);
print phi;

F := IntegralModel(E);
Q := SIntegralPoints(F, [2, 47]);
print "Computed!";

for P in Q do
    P;
    quit;
end for;

print "Done!";