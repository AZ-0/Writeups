# Cozzmic Dizzcovery

| Category | Author   | Solves | Points |
---------- | -------- | ------ | ------ |
| Crypto   | Polymero |      3 |   499  |

> "See that comb over there? It came from that meteorite I mentioned yesterday. Take a look at this, if I send bytes in, different bytes come out! Then there's this button that seems to just produce random bytes... I'm absolutely stumped :S"

#### Attachments:
- [pandorascomb.py](./pandorascomb.py)

## Solve
Full code in [solve.py](./solve.py).

Okay, so what do we have here? Let's look at what happens if we send the value `x` through the direction `0`.

```yml
direction 0 -->
      # internal state of the column
x -> | a | b | c | d | e | f | g | h | i | -> ?
```

The equation is: `ray = state[i] <- ray ^ state[i]`, that is when the ray interacts with a cell it is xored with it, updating *both* the ray and the content of the cell.

```yml
direction 0 -->
      # internal state of the column
x -> | a ^ x | b ^ a ^ x | ... | -> i ^ h ^ g ^ f ^ e ^ d ^ c ^ b ^ a ^ x
```

Since everything is linear we can play symbolically around with it in sage, nice.

```py
K.<x> = GF(256)
P.<a,b,c,d,e,f,g,h,i,j,k> = K[]
state = [*P.gens()]

def propagate(x, base=state):
    res = []
    for b in base:
        x += b
        res.append(x)
    return res

def repeat(x, n, base=state):
    for _ in range(n):
        base = propagate(x, base)
    return base
```

After a bit of fiddling around, we stumble on a most interesting result:

```py
sage: repeat(0, 16) # column of length 11 (direction 1 to 4)
[a, b, c, d, e, f, g, h, i, j, k]

sage: repeat(0, 16, state[:-2]) # column of length 9 (direction 0 and 5)
[a, b, c, d, e, f, g, h, i]
```

Sending `0` 16 times through the same ray fixes the internal state! This means we can recover without too much problems. Indeed, after each ray we know the content of the last cell in the ray.

```py
def repeat(x, n, base=state):
    for _ in range(n):
        base = propagate(x, base)
        print(base[-1])
    return base
```
```py
sage: repeat(0, 16)
a + b + c + d + e + f + g + h + i + j + k
a + c + e + g + i + k
b + c + f + g + j + k
c + g + k
a + b + c + h + i + j + k
a + c + i + k
b + c + j + k
c + k
d + e + f + g + h + i + j + k
e + g + i + k
f + g + j + k
g + k
h + i + j + k
i + k
j + k
k
[a, b, c, d, e, f, g, h, i, j, k]
```

Remember that `+` means xor here. It is very easy to retrieve the internal state! Additionally, the same kind of symbolic fiddling reveals that the equations are the same to retrieve a ray of length 9.

```py
def recover_ray11(indir: int) -> list:
    for _ in range(5):
        oracle(indir)

    acik = oracle(indir)
    bcjk = oracle(indir)
    ck = oracle(indir)
    defghijk = oracle(indir)
    egik = oracle(indir)
    fgjk = oracle(indir)
    gk = oracle(indir)
    hijk = oracle(indir)
    ik = oracle(indir)
    jk = oracle(indir)
    k = oracle(indir)

    j = jk ^ k
    i = ik ^ k
    h = hijk ^ i ^ j ^ k
    g = gk ^ k
    f = fgjk ^ g ^ j ^ k
    e = egik ^ g ^ i ^ k
    d = defghijk ^ e ^ f ^ g ^ h ^ i ^ j ^ k
    c = ck ^ k
    b = bcjk ^ c ^ j ^ k
    a = acik ^ c ^ i ^ k

    return [a, b, c, d, e, f, g, h, i, j, k]

def recover_ray(indir: int) -> list:
    ray = recover_ray11(indir)
    if 1 < indir < 5:
        return ray
    return ray[2:]

def recover_comb() -> PandorasComb:
    key = []
    for x in range(6):
        key.extend(recover_ray(x))
    return PandorasComb(key)
```

Now that we know the internal state of the comb, we can get the flag by emulating what happens at each shooted byte.

```py
def recover_flag(comb: PandorasComb):
    print('='*200)
    dirs = [read_tuple() for _ in range(57)]

    flag = []
    for indir, res in dirs:
        path = SHOOT_DIC[indir]
        # res = i ^ h ^ g ^ f ^ e ^ d ^ c ^ b ^ a ^ f
        f = res ^ reduce(xor, [comb.state[x][y] for x, y in path])
        print(chr(f), end='')

        flag.append(f)
        comb.shoot(indir, f) # update the state

    print('\n', '='*200, sep='')
    return flag
```