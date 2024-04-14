from sage.all import QQ, polygens, EllipticCurve_from_cubic
from hashlib import sha256
from tqdm import trange

X,Y,Z = polygens(QQ, 'x,y,z')
phi = EllipticCurve_from_cubic(X**3 + Y**3 - 94*Z**3)
E = phi.codomain()
P, = E.gens()
R = P

for _ in trange(2**10):
    psi = phi.inverse()
    Q = psi(R)
    Q.clear_denominators()
    x,y,z = Q
    if x>0 and y>0:
        print('FOUND!!!')
        print('x =', x)
        print('y =', y)
        print('z =', z)
        h = sha256(str(z).encode()).hexdigest()
        h = f"FCSC{{{h}}}"
        print(h)
        with open('found.txt', 'a') as file:
            file.write(h)
        break
    R += P