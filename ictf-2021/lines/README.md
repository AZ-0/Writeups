# Lines
#### **Category:** Crypto
#### **Author:** Eth007
#### **Points:** 150
#### **Description:**
> Try to crack my unbreakable™ encryption! I based it off of the Diffie-Helman key exchange!
#### **Attachments:** [lines.py](./lines.py), [out.txt](./out.txt)

## Understanding the challenge

So the script does a bunch of maths modulo some (known) integer `p`.
We have the following:

- `flag` (unknown)
- `msg` (known)

- `p = <big big prime>` (known)
- `g = 2`
- `a = <random in [0, p]>` (unknown)
- `b = <random in [0, p]>` (unknown)
- `s = (g^a)^b % p = g^(ab) % p` (unknown)
- `enc(x) = s*x % p`

- `enc(flag)` (known)
- `enc(msg)` (known)

**Goal:** Find the flag (no joke)

## Solving the challenge

When doing modular arithmetic, not only can we multiply by some `x` but also *divide* (and still get integers!). To do that we basically go the other way around and search a number `y` such that `xy = 1 % p`. We call `y` the [modular inverse](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse) of `x`, and denote it `y = x^-1`.

So since multiplication retains (nearly) all the nice properties we want when reducing modulo some integer, we can compose some of the knowns we know to know unknowns.

For instance, we might want to know `s` (why not?): `enc(msg) = msg*x % p <=> s = enc(msg) * msg^-1 % p`. So, we can mark that as a known. We might also want to know the `flag`: `enc(flag) = flag*s % p <=> flag = enc(flag)*s^-1 % p`.

Welp, looks like we're already done o_O

```py
from Crypto.Util.number import bytes_to_long, long_to_bytes
msg = bytes_to_long(b":roocursion:")

p = ...
g = 2

enc_flag = ...
enc_msg = ...

s = pow(msg, -1, p) * enc_msg % p
flag = pow(s, -1, p) * enc_flag % p

print(long_to_bytes(flag))
```