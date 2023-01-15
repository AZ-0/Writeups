# HADIOR

| Category | Author   | Solves | Points |
---------- | -------- | ------ | ------ |
| Crypto   | Polymero |      3 |   499  |

> "HADIOR will hold the DOOR."

#### Attachments:
- `nc ctf.k3rn3l4rmy.com 2241`
- [hadior.py](./hadior.py)

## Solve
Forgery generating code in [solve.py](./solve.py)

This is a DSA challenge, where you need to forge a signature. However, the `sign` and `verify` function are a bit peculiar:

```py
    def d(self, x):
        if type(x) == bytes:
            x = bytes_to_long(x)

        x %= self.p
        return sum(int(i) for i in list('{:0512b}'.format(x ^ self.sk)))

    def sign(self, m):
        p, q, g = self.p, self.q, self.g

        k = randbelow(q)
        r = pow(g, k, p) % q
        s = pow(inverse(k, q) * (self.h(m) + self.sk * r), self.d(m), q)
        return r, s

    def verify(self, m, r, s):
        p, q, g = self.p, self.q, self.g

        h = self.h(m)
        d = self.d(m)

        if d % 2:
            s = pow(s, inverse(d, q - 1), q)
            u = inverse(s, q)
            v = (h * u) % q
            w = (r * u) % q
            return r == pow(g, v, p) * pow(self.pk, w, p) % p % q

        lst = []
        root = modular_sqrt(s, q)
        for si in [root, -root % q]:
            s = pow(si, inverse(d, q - 1), q)
            u = inverse(s, q)
            v = (h * u) % q
            w = (r * u) % q
            lst += [r == pow(g, v, p) * pow(self.pk, w, p) % p % q]

        return any(lst)
```

The `d` function gives the hamming weight of `x ^ sk`, where `x` is a number you have total control on and `sk` is the secret key.
The rest of the script handles errors and give *accurate* feedback, which in our case we could leverage to know whether `d(m)` was even or odd. Now with a bit of ingenuity, it might be possible to retrieve the secret key bit by bit and then use it to sign an arbitrary message.

I have no idea whether that's the solve idea.

This doesn't matter at all.

Yes, there is a cheese.


## The Cheese

If you've played crypto for a little while, you should be accustomed to a specific line of code:

```py
def verify(m, r, s):
    if r < 2 or r > q - 1 or s < 2 or s > q - 1:
        return False
```

The sole purpose of its existence is, in fact, to prevent the cheese we're about to unleash.

The security of DSA lies in that when you compute `g^v * pk^w = g^{u*(h + sk*r)}` the quantity depends on `r` so that you can't just set `r = g^v * pk^w`, and it depends on `sk` so that you can't just set `u = 1/s = 1/(h + r)`.

But what would happen if `s = 0`? Normally we shouldn't be able to even compute `u`, much less verify the signature. However, when you look at the code of `inverse` in the `Crypto.Util.number` module, you can see that there is *no* check to verify that you can actually compute the modular inverse:

```py
def inverse(u, v):
    """The inverse of :data:`u` *mod* :data:`v`."""

    u3, v3 = u, v
    u1, v1 = 1, 0
    while v3 > 0:
        q = u3 // v3
        u1, v1 = v1, u1 - v1*q
        u3, v3 = v3, u3 - v3*q
    while u1 < 0:
        u1 += v
    return u1
```

Sure enough, `inverse(0, whatever) = 0`. Now `s = 0` has a number of awful consequences:
- `u = inverse(0, q) = 0`
- `v = h * u = 0`
- `w = r * u = 0`
- `g^v * pk^w = g^0 * pk^0 = 1`

You can send `s = 0`, `r = 1` to the server to make it verify any and all messages.