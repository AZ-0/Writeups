# ZKPoD
#### **Category:** Crypto
#### **Author:** Robin_Jadoul
#### **Points:** 400
#### **Description:**
> *Pointing at a butterfly* Is this a zero knowledge proof of decryption?
#### **Attachments:** [zkpod.py](./zkpod.py)

## Symbols
| Symbol | Meaning |
| :----: | :------ |
| mod N  | The previous equality is a [congruence](https://en.wikipedia.org/wiki/Modular_arithmetic#Congruence) modulo `N` |
| % N    | The actual [modulo](https://en.wikipedia.org/wiki/Modulo_operation) operator |

## Understanding the challenge

We are given an [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) encrypted flag (the public key `(N, E)` being public).
The challenge server accepts infinitely many queries; one query performs the following:
 1. RSA decrypt user input (we aren't given the plaintexts)
 2. Sign the plaintext (more details on that below)
 3. Send the signature

Let `P` a BIG (known) prime and `g` a [primitive root](https://en.wikipedia.org/wiki/Primitive_root_modulo_n) modulo that prime. In our case `g = 2`.

The signature is done according to some warped [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm):
 1. Generate a random nonce `k` in `[0, P - 1)`
 2. Let `r = g^k mod P`
 3. Let `e = H(r)`, `H` being a known hash function
 4. Let `s = k - x*e mod P - 1`, `x` being the signed plaintext
 5. Output `(r, s)` as the signature

## Solving the challenge

Let `x` the (unknown) plaintext flag, `X = x^E % N` the (known) RSA encrypted flag.

So *what* can we send exactly?
It is pretty clear we can sign any arbitrary plaintext, by RSA encrypting it first and then sending it to the oracle.
We can also sign any message of the form `a x^m` by sending `a^E X^m` to the oracle: indeed, `(a^E X^m)^D = a^(ED) x^(EDm) = a x^m mod N` where `D` is the RSA private key.

It might be interesting to retrieve `g^x % P`, perhaps it will prove useful later on. Luckily, it's not hard to remove the random component out of a signature (when just sending `X` to the oracle):
```py
(r/g^s)^(1/e) = (g^k / g^{k - xe})^(1/e) mod P
              = g^(xe/e)                 mod P
              = g^x                      mod P
```

> Here `1/e` means the modular inverse of `e` modulo `P - 1` (look at [Fermat's Little Theorem](https://en.wikipedia.org/wiki/Fermat%27s_little_theorem) if you don't understand why this works here). If that modular inverse doesn't exist, no problem; ask for another signature until it exists.

What can we do now? It doesn't seem like there's any obvious way to attack the signature, is there? ~~must be why it's a 400 points chall~~

But... wait! All our equations until this point held under the assumption that everything mod `N` was the same as mod `P`. What if it wasn't?
Clearly, `x < N < P-1` so that `x % N = x = x % P-1`.
But we can also make it decrypt to `a*x^m`, and given sufficiently large `a` and/or `m` it's very likely that `a*x^m % N ≠ a*x^m % P-1`.

We might be onto something here! We know how to compute `g^(a*x^m % N) % P` from a given signature the same way we computed `g^x % P`. We can also compute `g^(a*x % P-1) % P` very easily because we know `g^x`: `g^(a*x % (P-1)) = (g^x)^a mod P`.

So let's say `m = 1` for now. We have a way of telling, for any arbitrary `a`, whether `ax > N` by simply checking whether `g^(ax % N) = g^(ax % P-1) mod P`. With this, we could in `O(log N)` queries find an `a` such that `ax < N ≤ (a + 1)x` and essentially be done since then `N/(a+1) ≤ x < N/a` and for large `a`, `N/(a+1) ≈ N/a`. Binary search, here we go!

> The complexity is more likely to be random polynomial time or something since there's a chance we have to retry the request, but I've no idea how to compute these so `O(log N)` will do just fine.

## Solve script

First things first, let us find `g^x % P` :D
```py
from zkpod import H
from math import gcd
from pwn import remote

N = ...
E = 0x10001
P = ...
g = 2
X = ...

io = remote('chal.imaginaryctf.org', 42012)

def e(r): # Yeah I lied it's not *directly* e = H(r)
    return H(str(r).encode() + b"Haha, arbitrary message")

def sign(c):
    io.sendlineafter('> ', hex(c)[2:])
    r = int(io.recvline()[3:].decode())
    s = int(io.recvline()[3:].decode())
    if gcd(e(r), P-1) > 1: # If 1/e % P-1 doesn't exist, retry
        return sign(c)
    return r, s

def extract(r, s): # (r/g^s)^(1/e)
    return pow(r * pow(g, -s, P), pow(e(r), -1, P-1), P)

gx = extract(*sign(X))
```

Now let's do some binary search!
```py
def equals(a):
    c = X * pow(a, E, N) % N
    # True if a*x < N, False otherwise    
    return extract(*sign(c)) == pow(gx, a, P)

# Arbitrary upper/lower bounds to init search
upper = N//2**(15*16)
lower = N//2**(16*16)

from math import log2
print('Queries:', log2(upper - lower))

assert not equals(upper)
assert equals(lower)

while upper - lower > 1:
    try:
        mid = (upper + lower) // 2
        if equals(mid):
            lower = mid
        else:
            upper = mid
        print(upper, '> a >', lower)
    except EOFError: # Timeout
        io.close()
        io = remote('chal.imaginaryctf.org', 42012)

io.close()
print('='*210)
print('Lower multiplier:', lower)
print('Upper multiplier:', upper)

x = N//lower # There's only 1 bit of difference with N//upper so we can just test that
print(x.to_bytes((x.bit_length()+7)//8, 'big'))
```
This took quite long to run, because `log2(upper - lower)` is still like 1400 queries.