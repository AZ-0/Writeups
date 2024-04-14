########################### CHALL ###########################
p = 931620319462745440509259849070939082848977
d = 16
n = 16
B = 1 << (16*8)
nbits = p.nbits()

from json import loads
with open('output.txt', 'r') as file:
    data = loads(file.read())

iv  = bytes.fromhex(data['iv'])
enc = bytes.fromhex(data['flag_enc'])
shares = data['shares']

K, X = GF(p)['X'].objgens()

xs = [s[0] for s in shares]
ys = [s[1] for s in shares]

print('Solving...')

########################### SOLVE ###########################
nvars = d + 1 - n # d: degree of polynomial, n: amount of given points

F = PolynomialRing(GF(p), names=','.join(f'y{i}' for i in range(nvars)))
K.<X> = F.fraction_field()[]

points = [*zip(xs, ys)] + [*enumerate(F.gens())]
Q = K.lagrange_polynomial(points)
Q = K([1 * c for c in Q.list()]) # force evaluation of denominators, otherwise it can be stuck on things like a*y/a for some reason
print('Q =', Q)

coeffs = []
for g in F.gens() + (F(1),):
    coeffs.append([F(c).monomial_coefficient(g).lift() for c in Q.list()])
print('coeffs =', coeffs)

M = matrix(ZZ, coeffs)
I = identity_matrix(ZZ, M.nrows())
P = identity_matrix(ZZ, M.ncols()) * p
Z = zero_matrix(ZZ, P.nrows(), I.ncols())
N = vector(ZZ, [0]*(P.nrows() + M.nrows() - 1) + [1 << 3*nbits])

print('Running LLL...')
B = Z.stack(I).augment(P.stack(M)).augment(N)
L = B.LLL()

for v in L:
    if v[I.ncols() - 1] == 1:
        print('v =', v)
        break
else:
    print('Something went wrong!')
    print(L.str())

points[-nvars:] = enumerate(v[:nvars])
f = GF(p)['X'].lagrange_polynomial(points)
print('f =', f)

########################### FLAG ###########################
from Crypto.Cipher import AES

key = int(f.constant_coefficient()).to_bytes(16, 'big')
E = AES.new(key, mode = AES.MODE_CBC, iv = iv)
print(E.decrypt(enc))

key = int(f.constant_coefficient()).to_bytes(16, 'little')
E = AES.new(key, mode = AES.MODE_CBC, iv = iv)
print(E.decrypt(enc))