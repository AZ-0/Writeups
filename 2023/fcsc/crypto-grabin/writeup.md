# Grabin

Category | Author | Solves | Points
-------- | ------ | -----: | -----:
Crypto   | Un collègue qui n'est pas sur discord   | 3      | 495

> Nous avons imaginé une méthode vraiment complexe pour chiffrer le flag !

**Challenge files:**
- `grabin.py`
- `out.txt`


## Approaching the challenge

The challenge implements gaussian integer arithmetic as well as a cipher named `Grabin`, which mimics the [rabin cryptosystem](https://en.wikipedia.org/wiki/Rabin_cryptosystem) in the ring $\mathbb Z[i]$.
Basically, it generates two random gaussian primes $p, q$ whose norm is prime and congruent to $5$ modulo $8$, and we are asked to find a quartic root modulo $n = pq$.

```py
def __init__(self, l = 256):
    re = randrange(2 ** l)
    im = randrange(2 ** l)
    p = G(re, im)
    while not p.isGoodPrime():
        p += G(randrange(2 ** 32), randrange(2 ** 32))

    q = G(re - im, re + im)
    while not q.isGoodPrime():
        q += G(randrange(2 ** 32), randrange(2 ** 32))

    self.l = l
    self.pk = p * q
    self.sk = (p, q)
```

```py
def encrypt(self, flag):
    # Random message
    re = randrange(2 ** self.l)
    im = randrange(2 ** self.l)
    m = G(re, im)

    # Encapsulation
    x = pow(m, 4, self.pk)
    m = f"({m.re},{m.im})".encode()
    k = sha256(m).digest()

    # Encrypt the flag
    iv = os.urandom(16)
    c = AES.new(k, AES.MODE_CBC, iv).encrypt(pad(flag, 16))

    # Return challenge values
    return x, iv, c
```

First, we need to understand how residues work in $\mathbb Z[i]$.
Call $n_p$ the norm of $p$: we have $(p)\cap\mathbb Z=n_p\mathbb Z$.
Indeed $(p)\cap\mathbb Z$ must be a prime ideal of $\mathbb Z$ containing $n_p$; recall that $n_p$ is prime in $\mathbb Z$ and that prime ideals of principal domains must be maximal.

Now the morphism $\mathbb Z\hookrightarrow \mathbb Z[i]\twoheadrightarrow \mathbb Z[i]/p$ has kernel $(p)\cap\mathbb Z=n_p\mathbb Z$, and the first isomorphism theorem shows it factors into a (natural!) injection $\mathbb Z/n_p\hookrightarrow\mathbb Z[i]/p$.
Even better, this map is an isomorphism.
In fact, we have the equality of indexes $$n_p^2 = [\mathbb Z[i] : (n_p)] = [\mathbb Z[i]:(p)] [(p):(n_p)]$$ so that $\mathbb Z[i]/p$ can only have cardinality $n_p$ or $n_p^2$.
In the latter case we would have $p\mathbb Z[i]=n_p\mathbb Z[i]$, which is to say that $n_p\mid p$ in the gaussians.
However $n_p=p\bar p$, and $n_p$ being associated to $p$ would contradict uniquess of the factorisation.
In other words $|\mathbb Z[i]/p| = |\mathbb Z/n_p|$ and the injection is also surjective.

Now thanks to the chinese remainder theorem this becomes $$\mathbb Z[i]/n\cong\mathbb Z[i]/p\times\mathbb Z[i]/q\cong \mathbb Z/n_p\times \mathbb Z/n_q\cong \mathbb Z/n_n.$$
The morphism from right to left is an inclusion, and the one from left to right — which we shall dub $f$ — is not much harder to compute.
It suffices to know the (unique!) integral representant $j$ of $i$ modulo $n$ to see that we must have $$f(a+ib) = a+jb.$$

Of course we must find $j$.
To do that, notice that if $U = u+iv$ then $\mathfrak{Im}\,Un = vn_x + un_y$.
Since $\mathrm{gcd}(n_x,n_y)=1$ we can find some $u,v$ such that $\mathfrak{Im}\,UN=1$.
In particular, if $A=a+ib$ is any gaussian integer then $\mathfrak{Im}\,A-b\,UN=0$ so that $f(A)= A-bUN\in\mathbb Z/n_n\mathbb Z$.
```py
def modint(A, N):
    _, v, u = xgcd(n.real(), n.imag())
    A -= n*(u + I*v)*A.imag()
    return A.real() % n.norm()

j = modint(I, n)
```
> Note that `modint` actually computes $\mathbb Z[i]/n\xrightarrow f \mathbb Z/n_n$ for all gaussian integers, not just $i\mapsto j$.
However this doesn't help us much, as the description of $f$ in terms of $j$ will prove much more convenient when working symbolically later on.

Given that the mathematical approach has proven quite fruitful to understand what's happening so far I'd expect there to be a beautiful algebraic attack on grabin, exploiting the structure of $\mathbb Z[i]$.
Accordingly I spend days reading introductory material on algebraic number theory, pertaining for instance to the factorisation of ideals in integral extensions.
Sadly, I don't find anything.

![Is this algebraic number theory?](memes/ant.jpg)

The rabin cryptosystem has also been considered for gaussian integers by cryptographers, yet all the papers I find only consider the case of Blum primes $p\equiv3\ [4]$.
They say that for non-Blum primes the cryptosystem "reduces to the classical case" (most likely because of the above isomorphism) without further description.

However, this doesn't account for the fact that we are given non-trivial information about $\mathbb Z/n_n$: we know $j$, a square root of $-1$, which in general should be hard to find without factoring $n_n$.
Perhaps it is enough to factor?
This unanswered [post](https://mathoverflow.net/questions/140147/difficulty-of-factoring-a-gaussian-integer-compared-to-factoring-its-norm), in particular, gave me hope that the answer actually existed somewhere in the depths of internet.
Yet again, I can't find anything of interest.

I also try to cast finding a square root of $x$ into the search of rationals points on a conic, but it turns out that solving this is not easier than the original problem.
Because the coordinates of $m$ are somewhat small, I try to coppersmith polynomials such as $(X + jY)^4 - f(x)$ or the resultant of $\mathfrak Re\ (X+iY)^4 - \mathfrak Re\ x$ and $\mathfrak Im\ (X+iY)^4-\mathfrak Im\ x$.
The resultant is an univariate polynomial of degree $16$, well outside the bounds of coppersmith; I suspect the bivariate polynomial also is, but for some reason clear bounds on bivariate coppersmith don't seem to exist.

Days wasted later, in a friendly conversation where he's asking about my progress, Genni jokes about how I made the same mistake as him.
Does this mean I missed something?

![read the chall file](memes/readchall.jpg)


## Approaching the challenge (for real this time)

Woops.
Looking through `challenge.py` again reveals that the prime are far from honest:
```py
re = randrange(2 ** l)
im = randrange(2 ** l)
p = G(re, im)
while not p.isGoodPrime():
    p += G(randrange(2 ** 32), randrange(2 ** 32))

q = G(re - im, re + im)
while not q.isGoodPrime():
    q += G(randrange(2 ** 32), randrange(2 ** 32))
```

We can model this as $p = a + ib + e_x + ie_y$ and $q = (a - b) + i(a + b) + f_x + if_y$, where $a,b<2^{256}$ are some integers and $e_x,e_y,f_x,f_y<2^{43}$ (experimentally) are some small errors.

This REEKS of coppersmith.
Which means we are going to need to do inequalities to see how much bits we can extract from $n_n$ as well as $n_x = \mathfrak{Re}\,n$ and $n_y=\mathfrak{Im}\,n$.
First things first, the sign of $n_x$ and $n_y$ tell us that $a<b$.

Writing $p$ and $q$ symbolically in sage, I see that the norm $n_n$ of $n$ is of the form $2(a^2 + b^2)^2 + O(2^{43}b^3)$, and that the norm $n_p$ of $p$ looks like $a^2 + b^2 + O(2^{43}b)$.
I attempt to coppersmith this directly, but we don't know enough bits of $a^2+b^2$ to perform a successful attack; bruting the remainder takes too long.

I search for other equations, and finally arrive at this:
$$\begin{aligned}
n_x &= p_xq_x - p_yq_y = a^2 - 2ab - b^2 + O(2^{43}b),\\
n_y &= p_xq_y + p_yq_x = a^2 + 2ab - b^2 + O(2^{43}b),\\
n_n &= n_pn_x = 2(a^2 + b^2)^2 + O(2^{43}b^3). 
\end{aligned}$$
This means we can extract the values $$X = \sqrt{n_n/2} = a^2 + b^2 + O(2^{21}b^{3/2})$$
and $$Y = \dfrac{n_x+n_y}2=a^2-b^2+O(2^{43}b).$$
Now $a$ is well approximated by $\sqrt{\frac{X+Y}2}$ and $b$ by $\sqrt{\frac{X-Y}2}$, we theoretically miss at most $56$ bits.
```hs
nx = ZZ(n.real())
ny = ZZ(n.imag())
nn = ZZ(n.norm())

X = isqrt(nn//2)
Y = (nx + ny)//2

ha = isqrt((X + Y)//2)
hb = isqrt((X - Y)//2)
```
Notwithstanding, taking square roots usually yields much better approximation than expected so I check against my own generated values.
Empirically, we only miss the $37$ least significant bits of $a$ and $b$!
This should be more than small enough to perform a coppersmith.
Except we can't know for sure.

![bounds on coppersmith](memes/bivariate.jpg)

Because $pq \equiv n\equiv0\ [n]$, passing through the isomorphism $\mathbb Z[i]/n\xrightarrow f\mathbb Z/n_n$ gives $$(p_x + jp_y)(q_x + jq_y) \equiv f(p)f(q) \equiv 0\ [n_n].$$
Since $f(p)$ and $f(q)$ are both non-zero, this means that $p_x + jp_y$ is a zero-divisor, ie has non-trivial gcd with $n_n$: it is in fact a multiple of $n_p$.
This motivates the definition of $$P(x, y) = (h_a + x) + j(h_b+y)\in (\mathbb Z/n_n)[x,y],$$ where $h_a$ and $h_b$ represent the known high bits of $a$ and $b$.
We have $P(l_a + e_x, l_b + e_y) = f(p)$ and $l_a + e_x, l_b + e_y < 2^{43}$.
Coppersmith should definitely work.
It definitely should.

But this is tweaking hell and I waste several more hours and finding the right parameters with three different implementations of Coppersmith until Defund's `small_roots` works on my locally generated $n$ with bounds $2^{37}$, $m=1$, and $d=5$!
It even works near instantly on everything I generate using the provided challenge file, so far so good.

```hs
R.<x, y> = Zmod(nn)[]
j = modint(I, n)

P = (ha + x) + j*(hb + y)
roots = small_roots(P, [2^37, 2^37], m=1, d=5)
print(roots)

g = gcd(P(*roots[0]).lift(), nn)
print(1 < g < nn)
p = gcd(n, g)
q = n//p

np = p.norm()
nq = q.norm()
assert nn == np*nq
```

Of course, for some unfathomable reason it doesn't work with the challenge parameters!

![It works locally](memes/remote.jpg)

It ultimately turned out I had messed up copying the content of `out.txt`

Only the easy part remains: we can find a quartic root of $x$ in $\mathbb Z/n_p$ and $\mathbb Z/n_q$, combine them using the chinese remainder theorem, and recover the complex representant of $m$ after moduloing by $n$.

```py
from Crypto.Cipher import AES
from itertools import product
from hashlib import sha256

for mp, mq in product(mps, mqs):
    m = mod(crt([mp.lift(), mq.lift()], [np, nq]), n)
    k = sha256(f"({m.real()},{m.imag()})".encode()).digest()
    pt = AES.new(k, AES.MODE_CBC, iv).decrypt(c)

    if b'FCSC' in pt:
        print('m =', m)
        print('pt =', pt)
        print()
```

Full solve in [solve.ipynb](solve.ipynb).