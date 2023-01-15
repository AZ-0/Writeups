# Formal Security Poop

> Despite Koblitz's hate speech, the security of this scheme has been *formally* proven. My secrets are safe forever!

| Category | Author | Solves | Points | Expected Difficulty |
| -------- | ------ | ------ | ------ | ------------------- |
| Crypto   | A~Z    |      6 |    497 | Hard                |

## Understanding the challenge

There are two files, `main.py` and some backend `ecc.py` that implements elliptic curve arithmetic.
The `ecc.py` file uses the standard formulae and instanciates some standard supposedly secure curve $E$ with generator $G$.
The `main.py` does a lot more.

Connecting to the remote gives 4 options:
- Storing a secret
- Retrieving a secret
- Signing a secret
- Reinitializing the session

### The session

To communicate, the server implements the [HMQV](https://en.wikipedia.org/wiki/MQV) protocol (it is not needed to know that this was used to solve the challenge).

If Alice and Bob want to communicate using this protocol, they need the following:
- a long-term keypair $a$, $A=aG$ (resp. $b$, $B=bG$).
- an ephemeral keypair $x$, $X=xG$ (resp. $y$, $Y=yG$).

They compute a shared secret, which is then used to derive a key for a symmetric cipher:
- $S = (x + H(X)a)(Y + H(Y)B)$ on Alice's side
- $S = (y + H(Y)b)(X + H(X)A)$ on Bob's side

The long-term keypair is fixed for the entirety of the communication with the remote, but the ephemeral keypair will change every time the session is reset.

The shared key is used to AES-encrypt the secrets, whenever they are received or sent by the server.

```py
y, Y, key = session()
# Communication is encrypted so that third parties can't steal your secrets!
aes = AES.new(key, AES.MODE_ECB)
```
```py
if opt == 1:
    owner = input("Who are you? ")
    secret = aes.decrypt(bytes.fromhex(input('secret = ')))
    vault.store(unpad(secret, 16), owner, A)
    print("Secret successfully stored!")

elif opt == 2:
    owner = input("Who are you? ")
    secret = pad(vault.retrieve(owner), 16)
    print("Here is your secret:")
    print('secret =', aes.encrypt(secret).hex())
```

### The secrets

All secret handling is done in the `Vault` class.
It is just a dictionary that to a name associates a public key and a stored secret.
```py
def store(self, secret: bytes, owner: str, P: Point):
    if owner not in self.secrets:
        self.secrets[owner] = P, secret
        return

    self.authenticate(owner)
    self.secrets[owner] = P, secret
```

Retrieving or modifying said secret is an authenticated operation, in which you need to prove you own the secret key that goes with the public key.
```py
def authenticate(self, owner: str) -> None:
    # Please see https://en.wikipedia.org/wiki/Proof_of_knowledge#Schnorr_protocol for how to interact
    # But we do it over ellipthicc curves, because we already have a group setup :D
    P, _ = self.secrets[owner]
    print(f"Please prove that you are {owner}:")

    T = Point.input("Give me the point T: ")
    print('c =', c := randbelow(p))
    s = int(input('s = '))

    if s*G == T + c*P:
        print("Successfully authenticated!")
    else:
        print("Who are you?? Go away!")
        exit()
```

Signing is unauthenticated and has an obvious vuln: ECDSA with 64-bits nonces when the curve has a 128-bits order.
With 2, 3 signatures you can retrieve the ephemeral key $y$, which is used as ECDSA-secret.
Thereafter, we will assume $y$ is a known quantity.
```py
def sign(self, owner: str):
    _, secret = self.secrets[owner]
    m = int.from_bytes(sha512(secret).digest(), 'big') % p

    k = randbelow(1 << 64) # [Note to self: make the bound dynamic on Y's order]
    r = (k*G).x
    s = (m + r*y)*pow(k, -1, p) % p
    # Verify the signature with (r, _) == (1/s)*(m*G + r*Y)
    return r, s
```

The goal is to retrieve the long term private key $b$ of the server, use it to authenticate as Bob and retrieve his secret, the flag.

## Solving the challenge

There is very little validation being performed on the points you can send to the server: $A$ gets no checks, and $X$ is only assumed not to be $0$.
This setup *begs* for an invalid curve attack!
But what can we do with it?
The most common application is to send a point with small order on a related curve, and find a secret quantity modulo that order by bruteforcing the discrete logarithm.

Let's imagine we did just that, and suppose we can solve the discrete log on our new curve.
Because $A$ and $X$ are not multiples of $G$ anymore, we can't compute the shared key.
Pretty sad, because if we did then we could bruteforce $b$ modulo the order and check the key derived from $S = (y + H(Y)b)(X + H(X)A)$ against the shared key.

However, there is another way to know if we used the right one: recall that the shared key is used to AES encrypt/decrypt the secrets when communicating with the server.
If we first store a known secret and then retrieve it, correctly AES-decrypting will mean that we have found the right shared key, hence the right $b$ modulo the order of $X + H(X)A$.

The only caveat is that we cannot change $A$ every session.
It needs to be low-order on every curve $E'$, and it even needs to lie on the server's curve $E$ in order for us to authenticate and retrieve our secret.
Luckily there is an easy solution: choose $A = 0$.

Putting it together, our strategy for solving will be as follow:
1. Send $A = 0$ as long term public key
1. Open a legitimate session and store some secret $m$
1. Repeat the following:
    1. Find a point $X$ of low order $o$
    1. Send $X$ as ephemeral public key
    1. If $H(Y)$ is not invertible modulo $o$, abort this iteration
    1. Recover $y$
    1. Authenticate to retrieve $c = \mathrm{ENC}_S(m)$
    1. Bruteforece $b$ modulo $o$ until $m = \mathrm{DEC}_S(c)$
1. End the loop when the lcm of the orders is greater than $p$.
1. Compute the crt of the remainders of $b$
1. Authenticate as Bob to retrieve the flag

Et voilà: `idek{HMQV_m4d3_K0bl1tz_4ng3ry}`. 🎉

The solve script is given in [`solve.sage`](./solve.sage).


As a side bonus, this chall was inspired by the hate letter Koblitz addressed to a number of theoretic cryptographers.
- Here it is: http://www.ams.org/notices/200708/tx070800972p.pdf
- And here are some answers: https://www.wisdom.weizmann.ac.il/~oded/X/pmc-ltr.txt, http://www.cs.umd.edu/~gasarch/BLOGPAPERS/koblitz.pdf.

This makes for a fun read :p
