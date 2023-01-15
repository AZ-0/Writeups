# Roll It Back
#### **Category:** Crypto
#### **Author:** Robin_Jadoul
#### **Points:** 300
#### **Description:**
> Once you figure out what this is doing, it could be a straight line to the finish.
#### **Attachments:** [roll_it_back.py](./roll_it_back.py)

## Understanding the challenge

So we are given a file with some functions like `x`, `t`, one constant `T = t(x(b"jctf{not_the_flag}", b"*-*")) | 1`, some flag manipulation and an output:
```haskell
l = 420
flag = 2535320453775772016257932121117911974157173123778528757795027065121941155726429313911545470529920091870489045401698656195217643
```
where `l` is the bitlength of the flag and `flag` is the manipulated flag.

**Goal:** Reverse the manipulated flag shenaningans to retrieve the real flag.

## Solving the challenge

The first thing to notice is that we need *not* reverse `x` and `t`; they are only ever used to compute `T`, so let's compute it once and forall and forget about them: `T = 136085`.

```py
from gmpy2 import popcount
T = 136085

with open("flag.txt", "rb") as f:
    flag = int.from_bytes(f.read(), "little")
    l = flag.bit_length()

print(f"{l = }")
for _ in range(421337):
    flag = (flag >> 1) | ((popcount(flag & T) & 1) << (l - 1))

print(f"{flag = }")
```

One very much used function, however, is `popcount` from gmpy2. The documentation is pretty clear, nice!
> `popcount(x)` returns the number of bits with value 1 in `x`. If `x < 0`, the number of bits with value 1 is infinite so -1 is returned in that case.

Now, we need to understand what one round does:
 1. One bit `b` of information is computed from the current flag.
 2. The least significant bit of the flag is forgotten.
 3. `b` is prepended to the current flag.

What we really need is to be able to compute the forgotten bit, knowing `b` and the flag at step 2.

Let us consider the following two cases:
1. At step 1, the lsb is 0: Let `n := popcount(flag & T)`
2. At step 1, the lsb is 1: Let `m := popcount(flag & T)`.

In fact, `m = n + 1`! Indeed, the lsb of `T` is 1, so that the lsb of the flag isn't lost through the bitwise and. Therefore, setting only that bit to 1 is guaranteed to increase the amount of 1 in the binary representation by exactly 1. In particular, they haven't got the same parity so their least significant bit is also different.

Given `flag` at step 3 (that is, given `b` and `flag` at step 2), we can thus recover `flag` at step 1 by making one guess for the least significant bit and checking whether it matches with `b`:
```py
from gmpy2 import popcount

def rev(flag): # flag at step 3
    b = flag >> l - 1
    flag = flag << 1 & 2**l - 1 # flag at step 2

    # We computed as if the lsb was 0.
    # The real lsb is 1 iff the result is different from b,
    # that is iff the xor returns 1.
    return flag | b ^ popcount(flag & T) & 1 # flag at step 1
```

We just have to repeat this 421337 times!
```py
T = 136085
l = 420
flag = ...

for _ in range(421337):
    flag = rev(flag)

print(flag.to_bytes((l+7)//8, 'little'))
```