# Poly-Proof

| Category | Author   | Solves | Points |
---------- | -------- | ------ | ------ |
| Crypto   | Polymero |     11 |   490  |

> "They asked me to set up a zero-knowledge proof that runs in polynomial time. I don't know what that means but I assume they want me to use polynomials, right?"

#### Attachments:
- `nc ctf.k3rn3l4rmy.com 2232`
- [polyproof.py](./polyproof.py)

## Solve
In this challenge, the flag is seen as a polynomial with its bytes as coefficients. Then each coefficient is multiplied by FIFTEEN freaking random bytes (I'll tell you now, for the rest of the challenge this is just mad). You can query 8 evaluation of the polynomial.

First things first, retrieve the polynomial. We know that every coefficient is a positive integer, so we can use this one trick: If `m > c_i` for each coefficent `c_i`, then writing `P(m)` in base `m` will yield all of the `c_i`.

Now here's our plan: connect a lot of times to the server, get the coefficients, gcd each attempt to hell and back. With enough iterations this should make the multiple of the flags small enough that we can guess it by looking at all the possibilities.

By running [`get_data.py`](./get_data.py) for some time (more than two thousand server queries), we get an array of multiples:
```py
multiples = [204, 432, 388, 412, 123, 218, 104, 242, 196, 102, 380, 396, 242, 99, 216, 102, 380, 242, 96, 234, 228, 190, 230, 102, 99, 228, 102, 232, 460, 190, 104, 110, 400, 190, 230, 104, 220, 196, 232, 196, 244, 204, 380, 242, 96, 234, 456, 380, 196, 220, 224, 234, 464, 115, 95, 96, 228, 190, 208, 52, 230, 190, 232, 208, 98, 460, 190, 112, 52, 220, 400, 102, 109, 98, 99, 190, 440, 96, 116, 190, 232, 104, 234, 206, 208, 232, 190, 242, 96, 234, 190, 104, 220, 484, 116, 208, 98, 220, 103]
```

Guessing that the flag charset is usual (letters + numbers + `'_{}'`), we can guess each character by making probable words:

```py
from string import ascii_letters, digits
alpha = ascii_letters + digits + '_{}'

flag = [[a for a in alpha if t % ord(a) == 0] for t in multiples]
print(flag)
```
```py
[['f', 'D', '3'],
 ['l', 'H', '0', '6'],
 ['a'],
 ['g'],
 ['R', '{'],
 ['m'],
 ['h', '4'],
 ['y'],
 ['b', '1'],
 ['f', '3'],
 ['L', '_'],
 ['c', 'B', 'H', 'X'],
 ['y'],
 ['c'],
 ['l', 'H', '0', '6'],
 ['f', '3'],
 ['L', '_'],
 ['y'],
 ['0'],
 ['u', 'N'],
 ['r', 'L', '9'],
 ['_'],
 ['s'],
 ['f', 'D', '3'],
 ['c'],
 ['r', 'L', '9'],
 ['f', '3'],
 ['t'],
 ['s'],
 ['_'],
 ['h', '4'],
 ['n', '7'],
 ['d', 'P', '2'],
 ['_'],
 ['s'],
 ['h', '4'],
 ['n', '7'],
 ['b', '1'],
 ['t'],
 ['b', '1'],
 ['z'],
 ['f', 'D', '3'],
 ['L', '_'],
 ['y'],
 ['0'],
 ['u', 'N'],
 ['r', 'L', '9'],
 ['L', '_'],
 ['b', '1'],
 ['n', '7'],
 ['p', '8'],
 ['u', 'N'],
 ['t'],
 ['s'],
 ['_'],
 ['0'],
 ['r', 'L', '9'],
 ['_'],
 ['h', '4'],
 ['4'],
 ['s'],
 ['_'],
 ['t'],
 ['h', '4'],
 ['b', '1'],
 ['s'],
 ['_'],
 ['p', '8'],
 ['h', '4'],
 ['n', 'X', '7'],
 ['d', 'P', '2'],
 ['f', '3'],
 ['m'],
 ['b', '1'],
 ['c', 'B'],
 ['_'],
 ['n', 'X', '7'],
 ['0'],
 ['t'],
 ['_'],
 ['t'],
 ['h', '4'],
 ['u', 'N'],
 ['g'],
 ['h', '4'],
 ['t'],
 ['L', '_'],
 ['y'],
 ['0'],
 ['u', 'N', '4'],
 ['L', '_'],
 ['h', '4'],
 ['n', '7'],
 ['y'],
 ['t'],
 ['h', '4'],
 ['b', '1'],
 ['n', '7'],
 ['g']]
```

`flag{m4yb3_cycl3_y0ur_s3cr3ts_4nd_s4n1t1z3_y0ur_1nputs_0r_h4s_th1s_p4nd3m1c_n0t_t4ught_y0u_4nyth1ng}`