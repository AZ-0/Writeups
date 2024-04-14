def symxor(x, y):
    return [a+b for a,b in zip(x,y)]

def symround(x, t):
    y = [None]*4
    y[0] = x[0] + t
    y[1] = x[1] + y[0]
    y[2] = x[2] + y[1]
    y[3] = x[3] + y[2]
    return y

def symexpand(k):
    rk = [k]
    for i in range(10):
        rk.append(symround(rk[-1], ts[i]))
    return rk

def symenc(p, rk):
    c = p[:]
    for i, sk in enumerate(rk[:-1]):
        c = symxor(c, sk)
        for j in range(5):
            c = symround(c, ss[5*i+j])
    return symxor(c, rk[-1])

def vars(*args):
    names = args[::2]
    ns = args[1::2]
    return ','.join(
        ','.join(
            f"{name}{i:0>2}"
            for i in range(n)
        )
        for name, n in zip(names, ns)
    )


p  = bytes.fromhex("0dfa4c6052fb87ef0a8f03f705dd5101")
c  = bytes.fromhex("d4ed19e0694101b6b151e11c2db973bf")
iv = bytes.fromhex("cd31cb6e6ded184efbb9a398e31ffdbb")
flag_enc = bytes.fromhex("653ec0cdd7e3a98c33414be8ef07c583d87b876afbff1d960f8f43b5a338e9ff96d87da4406ebe39a439dab3a84697d40c24557cd1ea6f433053451d20ce1fbf191270f4b8cc7891f8779eb615d35c9f")

R = GF(2)[vars('p',4, 'x',4, 't',10, 's',50)]
ps = R.gens()[:4]
xs = R.gens()[-64:-60]
ts = R.gens()[-60:-50]
ss = R.gens()[-50:]

rk = symexpand(xs)
symc = symenc(ps, rk)
for ci in symc:
    print('-'*50)
    print(ci)


print('*'*100)

M = matrix(ZZ, [
    [ci.monomial_coefficient(gi) for gi in R.gens()]
    for ci in symc
]).LLL().change_ring(GF(2))
print(M)

g = vector(R, R.gens())
V = GF(2)^R.ngens()

for v in M.row_space():
    w = sum(map(int, v))
    if w < 25:
        print(w, '|', g * V(v))

print('\n'+'*'*100+'\n')

for i, ki in enumerate(rk):
    print('-'*50)

    M = matrix(QQ, [
        [ci.monomial_coefficient(gi) for gi in R.gens()]
        for ci in ki
    ]).augment(matrix.identity(QQ, 4)).dense_matrix()

    D = matrix.diagonal(QQ, [1000]*R.ngens() + [1]*4)
    M = ((M*D).LLL()/D).change_ring(GF(2))

    for v in M:
        w = sum(map(int, v[:-4]))
        eq = ' + '.join(f'k{4-i}' if v[-i] else ' 0' for i in range(1,5))
        print(w, '|', eq, '=', g * V(v[:-4]))