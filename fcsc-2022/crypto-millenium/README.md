# Millenium

| Category | Author   | Solves | Points |
| -------- | -------- | ------ | ------ |
| Crypto   | Danhia   |     2  |   498  |

> Notre équipage de rebelles intergalactiques compte sur vous ! Jusqu'à présent notre organisation disposait d'un ordinateur quantique secret capable de contourner les protections cryptographiques mises en place par l'ennemi. Nous pouvions ainsi falsifier nos autorisations de déplacement en hyperespace.
> 
> Suspicieux, les agents de régulation des déplacements en hyperespace ont hélas mis au point une nouvelle méthode d'autorisation, appellée "millenium". Celle-ci résiste à notre ordinateur quantique. C'est la déroute ! Toutes nos équipes sont clouées au sol jusqu'à nouvel ordre.
> 
> Il y a une lueur d'espoir, la nouvelle méthode de signature a été hautement optimisée pour être efficace et a l'air de comporter une anomalie parallélépipédique. Nous avons besoin de vous pour retrouver la clé privée permettant de re-prendre le contrôle du réseau intergalactique. Nous avons isolé la partie que nous pensons vulnérable dans le fichier sign.py, pas besoin d'examiner le dossier secure_code. Nous avons réussi à mettre la main sur 300 000 signatures et la clé publique associée, cela devrait être suffisant pour trouver la clé secrète ennemie et signer une autorisation de déplacement pour un de nos vaisseaux.

> `nc challenges.france-cybersecurity-challenge.fr 2102`

## Understanding the challenge

We are given a (HUGE) file containing the following:

- `sign.py`
- `millenium_remote_server.py`
- a `data` folder, with `generate.py`, `pubkey.npy`, `sigs.py` (280 Mo!)
- a `secure_code` folder, following the description we won't bother with it for now

A quick look into `generate.py` reveals that it does exactly what it's supposed to do: generating 300k signatures and giving us the public key.

`millenium_remote_server` is pretty self explanatory: we're supposed to be able to forge a signature for an arbitrary message.
Since we are given so many signatures it'll probably be from recovering the private key.

The interesting file is obviously `sign.py`!
It begins with a lot of weird imports:
```py
import os
import sys
sys.path.insert(1, './secure_code')
from random import gauss
from Crypto.Hash import SHAKE256
from ntrugen import ntru_solve, gs_norm
from ntt import ntt, intt, div_zq, mul_zq, add_zq
from fft import fft, ifft, sub, neg, add_fft, mul_fft
from common import q
from math import sqrt
```
*Proceeds not to notice the sys.path.insert*

Perhaps it's some library? Googling `python "ntrugen"` immediately yields a very interesting repository: https://github.com/tprest/falcon.py.
It has got all the files we need (ntrugen, ntt, fft, common) as well as their dependencies!

We've learned something important: the challenge implements [Falcon](falcon-sign.info/), a signature scheme.

Pulling the repo and plugging the imports into `sign.py`, we run the `test` function:
```py
def test():
    sk = prvkey_gen()
    pk = pubkey_gen(sk)

    for _ in range(256):
        message = os.urandom(32)
        sig = sign(sk, message)
        assert verify(pk, message, sig)

if __name__ == "__main__":
    test()
```
And surprise! The assert fails. Is this normal?

Asking an admin about it, they answer that they won't answer. I guess it's normal then.
Only now do I notice that it's supposed to run on the files in `secure_code.py`: a few `diff -y` show that they are exactly the same as the repo's modulo some tiny changes.

- the documentation was stripped (the earlier mishap gave it back, neat)
- the value of `q` in `common.py`, described as "The integer modulus which is used in Falcon", has been changed from `12 * 1024 + 1` to `3*2*128+1`. Since we are supposed to recover the private key, it's probably so that the solve doesn't run forever.

![crypto vs web](./memes/cryptovsweb.jpeg)

We are now armed to try and understand the meat of `sign.py`, which was obviously modified from the original. Luckily, the repo is well documented.

The function `prvkey_gen()` is basically the same as `ntrugen.py/ntru_gen()`.
> Implement the algorithm 5 (NTRUGen) of Falcon's documentation.
At the end of the function, polynomials `f, g, F, G` in `Z[x]/(x ** n + 1)` are output, which verify `f * G - g * F = q mod (x ** n + 1)`.

Additionally, `f` and `g` are chosen especially so that they have very low norm (when considered as vectors, more on this later).

The function `pubkey_gen(sk)` is the last line of `falcon.py/PrivateKey.__init__`.
```py
# The public key is a polynomial such that h*f = g mod (Phi,q)
self.h = div_zq(self.g, self.f)
```
Here, `Phi = x^n + 1`: basically we do operations in `F_q[x]/(x^n + 1)`.

Following this naming convention, we shall call the public key `h`.

The function `hash_to_point(salt, message)` is the stripped version of `falcon.py/PrivateKey.hash_to_point`:
> Hash a message to a point in Z[x] mod(Phi, q).
> Inspired by the Parse function from NewHope.

Now begin the interesting things: the `sign` function has been modified!
Here is the corresponding part of the original (in `falcon.py/PrivateKey`):

```py
    def sample_preimage(self, point, seed=None):
        """
        Sample a short vector s such that s[0] + s[1] * h = point.
        """
        [[a, b], [c, d]] = self.B0_fft

        # We compute a vector t_fft such that:
        #     (fft(point), fft(0)) * B0_fft^-1 = t_fft
        # Because fft(0) = 0 and the inverse of B has a very specific form,
        # we can do several optimizations.
        point_fft = fft(point)
        t0_fft = [(point_fft[i] * d[i]) / q for i in range(self.n)]
        t1_fft = [(-point_fft[i] * b[i]) / q for i in range(self.n)]
        t_fft = [t0_fft, t1_fft]

        # We now compute v such that:
        #     v = z * B0 for an integral vector z
        #     v is close to (point, 0)
        if seed is None:
            # If no seed is defined, use urandom as the pseudo-random source.
            z_fft = ffsampling_fft(t_fft, self.T_fft, self.sigmin, urandom)
        else:
            # If a seed is defined, initialize a ChaCha20 PRG
            # that is used to generate pseudo-randomness.
            chacha_prng = ChaCha20(seed)
            z_fft = ffsampling_fft(t_fft, self.T_fft, self.sigmin, chacha_prng.randombytes)

        v0_fft = add_fft(mul_fft(z_fft[0], a), mul_fft(z_fft[1], c))
        v1_fft = add_fft(mul_fft(z_fft[0], b), mul_fft(z_fft[1], d))
        v0 = [int(round(elt)) for elt in ifft(v0_fft)]
        v1 = [int(round(elt)) for elt in ifft(v1_fft)]

        # The difference s = (point, 0) - v is such that:
        #     s is short
        #     s[0] + s[1] * h = point
        s = [sub(point, v0), neg(v1)]
        return s
```

Here is the "optimized" version:
```py
# this function has been HIGHLY optimized to be super efficient
def sign(sk, message):
    f, g, F, G = sk
    B0 = [
        [g, neg(f)],
        [G, neg(F)],
    ]

    r = os.urandom(40)
    point = hash_to_point(r, message)
    n = len(point)

    B0_fft = [[fft(elt) for elt in row] for row in B0]
    [[a, b], [c, d]] = B0_fft

    point_fft = fft(point)
    t0_fft = [(point_fft[i] * d[i]) / q for i in range(n)]
    t1_fft = [(-point_fft[i] * b[i]) / q for i in range(n)]

    z0 = [round(elt) for elt in ifft(t0_fft)]
    z1 = [round(elt) for elt in ifft(t1_fft)]

    z_fft = [fft(z0), fft(z1)]
   
    v0_fft = add_fft(mul_fft(z_fft[0], a), mul_fft(z_fft[1], c))
    v1_fft = add_fft(mul_fft(z_fft[0], b), mul_fft(z_fft[1], d))
    v0 = [int(round(elt)) for elt in ifft(v0_fft)]
    v1 = [int(round(elt)) for elt in ifft(v1_fft)]

    s = [sub(point, v0), neg(v1)]
    return r, s
```

There is only one difference, but it is big:
```py
z_fft = ffsampling_fft(t_fft, self.T_fft, self.sigmin, ...)
```
vs
```py
z0 = [round(elt) for elt in ifft(t0_fft)]
z1 = [round(elt) for elt in ifft(t1_fft)]

z_fft = [fft(z0), fft(z1)]
```

Last but not least, the `verify` function is a simplified version of (but as far as I can tell, functionally equivalent to) the original.
Basically, a signature `s = (s0, s1)` is considered valid if both `s0 + s1*h = point := Hash(salt || message)` as polynomials and `s` has very low norm as a vector.

### What didn't work

There are some things I tried here which didn't work but gave some insights on why the scheme is secure.

The first is: since we know `h`, can't we just set `f` to be some really smol polynomial, then let `g = fh`, and use that as our private key?
This didn't work, because even choosing an `f` with very low norm will result in moderately sized `g`.
In fact, as it will turn out later, it being hard to retrieve a valid `f` and `g` pair from `h` is exactly the NTRU assumption (what Falcon is based on).

Another attempt was picking random `s1` and computing `s0 = p - h*s1`, which same as above yielded way too big `s` vectors (usually they had more than 1000 times the maximal norm).

At this point, I am pretty certain the vulnerability is induced by the lack of randomness when picking `z`.

## Searching the Paper

All this fft stuff is quite scary, so it's better to do some preliminary search about how normal Falcon works (and whether there exist standards attacks, who knows?).

After a few rabbitholes about using side channels, I eventually find two papers:
 - https://eprint.iacr.org/2022/057.pdf (it's got parallelepipede in the name so it's interesting because of the chall description)
 - https://www.di.ens.fr/~prest/Publications/falcon.pdf (funny coincidence, it's written by the same guy as the repository)

They help me understand the scheme (it's much better explained than the actual specification), and the first one possesses a VERY interesting paragraph:

> Hidden Parallelepiped Problem.
In \[NR06\], Nguyen and Regev present an attack against the signature schemes NTRUSign \[HHP+03\] and GGH \[GGH97\], introducing the so-called Hidden Parallelepiped Problem (HPP).
The vulnerability of these two schemes comes from a correlation between the distribution of the signatures and the secret key.
With a few thousand signatures, the authors could recover the underlying private key.
As this attack will be revisited in our paper, we outline its principle.
>
> Assume that in the GPV framework, the last step proceeds as follows.
To find a vector v ∈ Λ close to c, the signer uses the private matrix B to perform the round-off algorithm \[Bab85, Bab86\].
In other words, v is defined as ⁅c B^-1⁆B. This procedure ensures that v is deterministically defined as a closest vector of c in Λ.
Thus, v − c belongs in the fundamental parallelepiped P(B) := { xB, x ∈ [−½, ½]^n } where n is the number of rows of B.

The process in our case was exactly altered so that we compute `v = ⁅c/B⁆ B`, which is the case outlined here.

Going to the references section, \[NR06\] is
> Phong Q. Nguyen and Oded Regev. Learning a parallelepiped: Cryptanalysis of GGH and NTRU signatures. In Serge Vaudenay, editor, EUROCRYPT 2006, volume 4004 of LNCS, pages 271–288, St. Petersburg, Russia, May 28 – June 1, 2006. Springer, Heidel-
berg, Germany. 8, 13, 17

Parallelepiped? Check. Dealing with our exact problem? Check.

This is a STONKS moment.

![right paper](./memes/rightpaper.jpg)

## Implementing the Attack

The paper is in open-access at https://link.springer.com/content/pdf/10.1007/11761679_17.pdf.

There's no mention of Falcon anywhere within.
However, I know by now that Falcon is an instantiation of the GPV framework using NTRU lattices (Scary words! But ultimately just definitions, look into the first two papers above for more details).
\[NR06\] being focused on breaking NTRUSign, it should be possible to warp the attack to fit our particular case.

At this point, it'll be useful to give an outline of how our version of the Falcon signing scheme works:

A polynomial `f = f0 + f1*x + ... + f{n-1} x^{n-1}` in `Z[x]/(x^n + 1)` is naturally associated to a matrix:
```haskell
    [      f0  f1  f2 ... f{n-1} ]  -- f
    [ -f{n-1}  f0  f1 ... f{n-2} ]  -- x*f
    [         ...     ...   ...  ] 
    [     -f1 -f2 -f3 ...    f0  ]  -- x^{n-1} * f
```
Basically, the `i-th` row corresponds to `x^i * f mod x^n + 1`.
These have a lot of nice properties, the most important of which being convolution of polynomials corresponds to multiplication of matrices.
For this reason, we can talk indifferently about pairs of polynomials `(x, y)` or vectors in `R^2n`.

1. Write the matrix `B = [ g  -f ] [ G  -F ]`.
1. Hash the message `m` into a point `p = Hash(random_salt || m)`. Let `c = (p, 0)`
1. Compute `t = c B^-1`.
1. Let `z = |t|` (where `|x|` denotes the rounding of `x`). -- this is the only step that significantly differs from Falcon
1. Set `v = z B`.
1. Return `s = c - v`.

`B` isn't chosen at random: it generates a lattice `L` whose points `(x, y)` are exactly those which verify `x + hy = 0` (recall that `h = g/f` is the public key).

Since `B` is composed of vectors with very low norm, `v = z B = |t| B = |p B^-1| B` is the nearest point to `c` that lies on the lattice.
Thus not only has `s = (s0, s1)` a low norm as well, it is constructed so that `s0 + s1*h = p`.

Indeed `v` belongs to `L`, the lattice generated by `B`, so that `s = c - v` lives in the affine space `c + L`.
Now the map `(x, y) → x + h*y` is linear of kernel `L` hence the image of `s` by this map is that of `c`. But `c = (p, 0)`, and `p + h*0 = p`.

The attack given by the paper leverages a particular property of `s`: It is defined by `s = c - v = t B - z B = (t - z)B = (t - |t|)B`.
The quantity `t - |t|` is a vector in `[-1/2, 1/2]^n`, so that `s` belongs to a space called the *fundamental parallelepiped* `P(L)` of the lattice `L` generated by `B`.
Essentially, `P(L)` is a dimension n generalization of the rectangle defined by the four lattice points closest to the origin.

We will follow three steps:

1. Approximate the gram matrix `G = B^t B` of `B`
1. Compute the cholesky factor of `G^-1` (that is, the unique lower triangular matrix `L` such that `G^-1 = L L^t`), and turn the hyper-parallelepiped into an unit hyper-cube by multiplying every vector on the right by `L`.
1. Use gradient descent on a well chosen function to retrieve the edges of the hyper-cube, yielding low norm vectors of `BL`: multiply by `L^-1` to get low norm vectors of `B`.

I have implemented this algorithm in sage.
It took FOREVER to run.
I have implemented this algorithm in numpy.

### First step
```py
def gram_approximation(vectors):
    '''Given random vectors v chosen uniformly on the parallelepiped P(B), approximates the gram matrix G = B^t B.
    This is the first step of Algorithm 1 in [NR06], given by Lemma 1 (Gram Leakage):
            B^t B = 3 Exp[v^t v]
    '''
    n = vectors.shape[1]
    A = np.zeros((n, n), 'int64')
    for v in tqdm(vectors, desc = 'Gram Approximation'): # tqdm gives nice progress bars
        A += np.mat(v).T @ np.mat(v)
    return 3*A/len(vectors)
```

`Exp[X]` is the expectation of a random variable `X`.
We can get a close approximation thanks to our 300k or so samples (which are assumed to be uniformly distributed).

### Second step
```py
def hypercube_transformation(G, vectors):
    '''Given (an approximation of) the gram matrix G of B, computes the map L such that P(BL) is an hypercube.
    This is step 2 and 3 of Algorithm 1 in [NR06], given by Lemma 2 (Hypercube Transformation).'''
    L = np.linalg.cholesky(np.linalg.inv(G))
    M = vectors @ L # computes all the vL at once 
    return L, M
```

### Third step
```py
def fourth_moment(w, vectors):
    '''mom{V,k}(w) = Exp[(u, w)^k].'''
    return np.mean((vectors @ w)^4)

def fourth_moment_gradient(w, vectors):
    '''∇mom{V,4}(w) = Exp[∇((u, w)⁴)] = 4 Exp[(u, w)³u].'''
    coeffs = (vectors @ w)^3
    return 4*(coeffs @ vectors)/len(vectors)
    # (coeffs @ vectors) contains the coefficiented sum for each coordinate

def learn_hidden_hypercube(n, δ, vectors):
    '''Algorithm 2 (Solving the Hidden Hypercube Problem by Gradient Descent) in [NR06].'''
    w = np.random.random(n)
    w /= np.linalg.norm(w) # we only want points on the unit sphere

    wnew = w - δ*fourth_moment_gradient(w, vectors)
    wnew /= np.linalg.norm(wnew)

    while fourth_moment(wnew, vectors) < fourth_moment(w, vectors):
        w = wnew
        wnew = w - δ*fourth_moment_gradient(w, vectors)
        wnew /= np.linalg.norm(wnew)

    return w
```

The fourth moment is a function whose local minima (on the unit sphere) are exactly the edges of the hypercube `P(BL)`.

This algorithm will give vectors `w` very near some edges of `P(BL)`, so that the `wl := w*L^-1` are very near some edges of `P(B)`.
Given a close enough approximation, simply rounding `wl` will yield a lattice point.

### Finishing

This algorithm is good and all, but a tiny teensy weeny problem remains: IT DOESN'T WORK!!! WHY?!

Rounding doesn't give point in the lattice; Babai's nearest plane algorithm (on the public basis) always yields 0; fpylll CVP implementation *aborts*.

![when the paper is wrong](./memes/paperiswrong.jpg)

After I've come this far it would be a shame to give up, so I generate my own 300k signatures to try and understand where the issue happens.
Several hours of debugging reveal the problem lies in the LAST place I'd expect it: the gram approximation is incorrect!

Further experimentation shows it's in fact only wrong up to a constant.
For some reason, we don't have `G = B^t B = 3 Exp[v^t v]` like in the paper but rather `G = B^t B = 12 Exp[v^t v]`.

Changing `L, cube_vectors = hypercube_transformation(G, vectors)` to `L, cube_vectors = hypercube_transformation(4*G, vectors)`, the algorithm miraculously works.
(but I don't notice and waste several more hours)

The gradient descent takes some time, so I run it through the night:
```py
candidates = []
best_candidates = []

δ = 0.7 # according to [NR06] this works well experimentally

# There's no need for a stop condition
# Working in a notebook means even if it gets interrupted the results won't be lost
# Notebooks are the best <3
while 1:
    print('iter...')
    wl = solve(L, δ, cube_vectors)
    wr = np.round(wl)
    g =  wr[:128]
    f = -wr[128:]

    g = [int(x)%q for x in g]
    f = [int(x)%q for x in f]

    if mul_zq(f, pk) == g:
        print('='*30, 'CANDIDATE', '='*30)
        print('wl =', wl)
        print('wr =', wr)
        print('Norm:', gs_norm(f, g, q))
        candidates.append(wl)
        try:
            F, G = ntru_solve(f, g)
            print('[+] Solved NTRU')
            sk = f, g, F, G
            print('sk =', sk)
        except ValueError:
            print('[!] Could not solve NTRU')
            continue

        best_candidates.append(wl)
        sgn = sign(sk, message)
        if verify(pk, message, sgn):
            print('[+] Successfully verified signature!')
```

By the early morning (2am) I get 10 low norm lattice points, one of which allows generation of the other components of the secret key.
However, it isn't small enough just yet to successfully sign messages!

That isn't a problem, because we can simply LLL reduce the vectors we got :D
```py
wrs = np.round(candidates)
for i, wr in enumerate(wrs):
    g = wr[:128]
    f = -wr[128:]
    assert vector([int(x) for x in sub(mul_zq(f, pk), g)]) % q == 0, i

A = matrix([[int(x) for x in wr] for wr in wrs])
B = A.LLL()
```
```py
for wr in B:
    g =  wr[:128]
    f = -wr[128:]
    try:
        F, G = ntru_solve(f, g)
    except:
        continue
    print('yaaay')
    break
```

Now to check it signs correctly:
```py
sk = f, g, F, G
sgn = sign(sk, message)
print(verify(pk, message, sgn))
```

We can connect to the remote and get the flag!

Full code in [`solve.ipynb`](./solve.ipynb)