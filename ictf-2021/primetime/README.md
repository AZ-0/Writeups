# Primetime
#### **Category:** Crypto
#### **Author:** puzzler7
#### **Points:** 300
#### **Description:**
> Alice and Bob are meeting up to watch TV, but they've neglected to invite Elise and Gamal! Elise and Gamal intercepted the network traffic between the two, and managed to extract an encrypted message. Can you help them figure out what TV show Alice and Bob will be watching, and when?
> 
> Wrap the decrypted message in the flag format before submitting.

#### **Attachments:** [primetime.py](./primetime.py), [output.txt](./output.txt)

## Understanding the challenge

The challenge revolves around a class `Element`. An `Element` encodes a number of bytes as a product of consecutive primes. We will thereafter denote an element by `{x}`, where `x` is the product of consecutive primes.
Let `E` the encoding function:
 - `E(0x421089) = {2^0x42 * 3^0x10 * 5^89}`

Addition between elements is defined in the following manner:
 - `{x} + {y} = {x × y}`, where `×` represents "multiplication with carry".

Multiplication with carry is defined so as to conserve the likeness with bytes. Whenever one of the prime has exponent greater than 255, it is reduced and the next prime receives another exponent. For instance, `{2^257} = {2^2 * 3^1}`.

This has the side effect that `E(a + b) = E(a) + E(b)`. Moreover, at all times, only the 16 first primes are kept; anything carrying over is shaved off. `E(a) = E(b) <=> a = b mod 256¹⁶`.

Multiplication also arises naturally from addition. I won't delve into the details; what matters is that it is defined so that `E(a * b) = E(a) * E(b) = a * E(b)`.

Now the script does some maths with these elements.
 - `gen  = E("+h3_g3n3ra+0r_pt") = E(0x2b68335f67336e3372612b30725f7074)`
 - `aKey = <random in [1, 2**128]>` (unknown)
 - `bKey = <random in [1, 2**128]>` (unknown)
 - `aPub = gen * aKey` (known)
 - `bPub = gen * bKey` (known)
 - `s = gen * aKey * bKey` (unknown)
 - `m = E(flag)` (unknown)
 - `c = m*s` (known)

**Goal:** Retrieve `m`

## Solving the challenge

Since `E` has all these nice properties, why don't we just reason in term of non-encoded numbers? Let `D` the inverse bijection of `E` (it shares the same properties).

Set the following:
 - `G  = D(gen)`
 - `AP = D(aPub) = G * aKey`
 - `BP = D(bPub) = G * bKey`
 - `S  = D(s) = G * aKey * bKey`
 - `M  = D(m) = flag`
 - `C  = D(c)`

Since addition, multiplication and whatnot are now simply modulo 2^128, it is therefore very simple to retrieve `S`, thus `M`, thus the `flag`:
 - `aKey = AP * G^-1 % 2^128`
 - `bKey = BP * G^-1 % 2^128`
 - `S = G * aKey * bKey % 2^128`
 - `M = C * S^-1 % 2^128`

## Solve script
```py
from primetime import ELEMENT_LEN, primes

def decode(n: int) -> int:
    dec = [0]*ELEMENT_LEN
    for i, p in zip(range(ELEMENT_LEN), primes()):
        while n % p == 0:
            dec[i] += 1
            n //= p
    return sum(dec[i] * 256**i for i in range(ELEMENT_LEN))

mod: int = 256**ELEMENT_LEN

gen  = ...
apub = ...
bpub = ...
c    = ...

G  = decode(gen)
AP = decode(apub)
BP = decode(bpub)
C  = decode(c)

aKey = AP * pow(G, -1, mod) % mod
bKey = BP * pow(G, -1, mod) % mod

S = G * aKey * bKey % mod
M = C * pow(S, -1, mod) % mod
print(M.to_bytes(ELEMENT_LEN, 'little'))
```