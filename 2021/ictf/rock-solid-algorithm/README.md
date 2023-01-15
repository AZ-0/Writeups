# Rock Solid Algorithm
#### **Category:** Crypto
#### **Author:** Eth007
#### **Points:** 100
#### **Description:**
> Something was the wrong size here...
#### **Attachments:** [secure.txt](./secure.txt)

## Understanding the challenge

Not a lot to do here. It's a classic [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) challenge instance where you're given `n`, `e`, `c` and try to decrypt it.

## Solving the challenge

First *suspicious* thing is `e = 5`. You would usually see `e = 65537`, `e = 3`, or even `e = 17`; but `e = 5`? For me, that's a first. Well, that doesn't break RSA in and of itself so let's move on and keep this in a corner of our head.

So, the description says, something is the wrong size. Let's look at the sizes then!
For instance, bitsize. We have `log2(n) = 1430` which once again is HIGHLY SUS. Usual values for that are `1024`, `2048`, or `4096`. HMMM.

One thing to know about textbook RSA (the one we're likely to encounter in CTFs) is that it's weak. There's no padding such as [OAEP](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding), which bring in a variety of attacks. In our case, let's look at the equation:
`c = flag^e % n`.
Simple right? But, isn't a flag usually like 35~40 chars? Will it even get reduced at all by the modulo?

If a flag is, say, 35 chars (ie 35 bytes, ie at most 280 bits) then that flag to the power of 5 will only be 280\*5 = 1400 bits. *Lower than n*. We're likely to be onto something here, let's rewrite the equation!
`c = flag^e - kn` for some integer `k`. If the flag is of usual length, it's very likely this `k` will be very smol.

Can't we just bruteforce it? We can, and we will!
```py
n = ...
e = 5
c = ...
k = 0

while 1:
    flag5 = c + k*n
    flag = int(flag5**(1/5))
    if flag**5 == flag5: # if we found a power of five
        print(k, flag.to_bytes(50, 'big'))
        break
    k += 1
```
This script finds the flag for `k = 19`