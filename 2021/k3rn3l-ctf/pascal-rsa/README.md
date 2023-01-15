# Pascal RSA

| Category | Author   | Solves | Points |
---------- | -------- | ------ | ------ |
| Crypto   | DrDoctor |    74  |   100  |

> RSA Encryption with Pascal's Triangle! Has to be secure right...

#### Attachments:
- [chall.txt](./chall.txt)
- [main.py](./main.py)

## Solve
It's an RSA where we are given the usual `N` and `c` and the lot less usual program to generate `d`.

```py
p = 751921

while len(triangle[-1]) <= p:
    r = [1]
    for i in range(len(triangle[-1]) - 1):
        r.append(triangle[-1][i] + triangle[-1][i+1])
    r.append(1)
    triangle.append(r)

code = ''
for x in triangle[-1]:
    code += str(x%2)

d = int(code, 2)
```

Essentially, this computes the p-th row of Pascal's triangle, then uses the parity of each cell for the bits of `d`. Now, we can't just run this to get the private key since it's waaaaaay too slow! Let's optimize it a bit with the amazing power of maths ~_~

The k-th cell of the p-th row in Pascal's triangle the binomial coefficient `pCk`. Now, there is a fancy little theorem called the binomial theorem:
![Shamelessly stolen from wikipedia](./wikipedia_binomial_theorem.svg)

Essentially, it tells us that binomial coefficients naturally arise as coefficients of the polynom `(x + y)ⁿ`. This theorem holds over any commutative ring, in particular F₂ (which we are interested in because it would give us the parity). It means to solve the challenge we only need to compute `(x + 1)^p` in `F₂[x]`.

As usual, sage is the solution to everything!
```py
K.<x> = GF(2)[]
d = sum(int(b) << i for i, b in enumerate((x + 1)^p))
int(pow(enc, d, N)).to_bytes(30, 'big')
```