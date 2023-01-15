# ECRSA

> ECDSA, ECDH, ECwhatever... Through the power of elliptic curves, every cipher can be made stronger. Idek️️️®️ is proud to prevent a new and improved version of RSA, the long-awaited ECRSA™️! This clever variant combines the modern with the classic, the powered with the elliptic, the unbreakable with the strong!

| Category | Author | Solves | Points | Expected Difficulty |
| -------- | ------ | ------ | ------ | ------------------- |
| Crypto   | A~Z    |     40 |    481 | Easy                |

## Understanding the challenge

This is a weird mix of RSA and elliptic curves.
Key generation for the former is done as usual, but everything after is a mess.

- We don't know $n$
- The flag is the x coordinate of a point $M$ on an elliptic curve $E$ over $\mathbb Z/n\mathbb Z$
- We don't know the parameters $a$ and $b$ of the curve

- We know that $e = 3$
- We are given $d$, the private RSA key
- We are given a point $T$ on $E$
- We are given $C := eM$ and $U := eT$

The goal is to recover $M$.
To achieve this, we will first need to retrieve $n$, $a$, and $b$.

## Solving the challenge

Since we are given 3 points, it is easy to recover a candidate for $a$ over $\mathbb Q$.
That is, we will get a value $a'\in\mathbb Q$ such that $a'\equiv a\ [n]$.

```py
K.<a> = QQ[]
f = U[0]^3 + a*U[0] - U[1]^2 + C[1]^2 - C[0]^3 - a*C[0]
a = f.roots()[0][0]
```

We will now compare the coordinates of $3T$ over $\mathbb Q$ with that of $U$.
Since they are supposedly congruent modulo $n$, this will give us two multiples of the latter.
Taking their gcd then yields a very small multiple, which we can run through factordb to remove small factors and get $n$.

```py
t = ZZ(int.from_bytes(b'ECRSA offers added security by elliptic entropy.', 'big'))
b = 2^2 - t^3 - t*a
E = EllipticCurve(QQ, [a, b])
T = E(t, 2)

xt3, yt3 = (3*T).xy()
n = gcd(xt3.numer() - U[0]*xt3.denom(), yt3.numer() - U[1]*yt3.denom())
print('n =', n)
```

Now, we only need to compute $e^{-1}C$ to get $M$...
But things are not so simple since it is hard to get the order of $E$ directly since $n$ is composite!

However, it is known that $E(\mathbb Z/n\mathbb Z)\cong E(\mathbb Z/p\mathbb Z)\oplus E(\mathbb Z/q\mathbb Z)$.
Factoring $n$ will enable us to compute $e^{-1}C$ over $E(\mathbb Z/p\mathbb Z)$ and $E(\mathbb Z/q\mathbb Z)$, and computing the CRT of their x coordinate will give the flag.

In this case, we can factorize $n$ because we know a multiple of $\varphi(n)$: $ed-1$.
```
fs = factorize(n, e*d - 1)
assert prod(fs) == n

ms = []
for p, _ in fs:
    Ep = EllipticCurve(GF(p), [a, b])
    ms.append([int(M[0]) for M in Ep(C).division_points(e)])

(p, _), (q, _) = fs
for mp, mq in it.product(*ms):
    m = CRT([mp, mq], [p, q])
    print(int(m).to_bytes(m.nbits()//8 + 1, 'big'))
```

Et voilà: `idek{Sh3_s3ll5_5n4k3_01l_0n_7h3_5e4_5h0r3}`. 🎉

The solve script is given in [`solve.sage`](./solve.sage).