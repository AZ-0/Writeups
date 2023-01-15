# Objection!

| Category | Author   | Solves | Points |
---------- | -------- | ------ | ------ |
| Crypto   | Polymero |      2 |   500  |

> "Looks like Harry is hoarding his flags again... Maybe he will stop if we can convince him both Alice and Carlo dislike hoarding too. Alice and Carlo, being stereotypical CTF admins, are not responding to your complaints. Guess you will just have to answer for them... Luckily, I managed to secure you a channel to the domain controller of the CTF server."

#### Attachments:
- `nc ctf.k3rn3l4rmy.com 2240`
- [objection.py](./objection.py)

## Solve
Full code in [solve.py](./solve.py)

This is another DSA signature forging challenge (not cheesable like HADIOR). We have three participants [Alice, Carlo, and Harry]; we need to send messages with forged signatures to Harry (impersonating Alice and Carlo).

We can:
- set the generator `g` of any participant
- send signed message to Harry

The flaw here is that the generator of participants need not be the same; by setting the right numbers we will be able to forge.

First, notice that if we set Harry's generator to Carlo's public key, the verifying equation will be of the form `g^v * pkC^w = pkC^{v + w}` which doesn't involve Carlo's secret key, meaning we can cancel the quantity `v + w` through our control on `s` and set `r = pkC`.

Basically, this would be the following:

```haskell
Generators:
    Carlo: (default)
    Harry: pkC

Forge Carlo:
    g = pkC
    r = pkC
    s = h + r

    g^v * pkC^w = pkC^{(h + r)/s}
                = pkC^{(h + r)/(h + r)}
                = pkC
                = r
```

Now, what to do for Alice? We can't repeat the same trick, because changing the generators a second time would reset our win count.

Ideally, we would like Harry's generator to be a power of both Carlo's and Alice's generators. Remember that `pkC = gC^xC`. If we set `gC = pkA` *before* forging, we will have `g = pkC = pkA^xC`.

Writing down the verifying equation, this yields the following:
```py
g^v * pkA^w = pkA^{xC*v + w}
            = pkA^{(xC*h + r)/s}
```

Alas, there is no obvious way to choose `r` and `s` such that `r = g^v * pkA^w`. This means we don't have enough control! ><

Luckily, we have already seen that powers of `pkC` and of `g` will still be powers of `pkA`. If we set `g = pkC^b` instead, the verifying equation becomes

```py
g^v * pkA^w = pkA^{xC*v*b + w}
            = pkA^{(xC*h*b + r)/s}
            = pkC^{h*b/s} * pkA^{r/s}
```

where we have total control on `b`, `r`, and `s`.
Now if we had `hb = r` and `s = r`, everything would simplify to `pkC * pkA` which we can compute independently of `r`.

Since the verifying equation is taken mod `P` then mod `Q`, we have the values:
- `r = pkC * pkA % P % Q`
- `b = r/h = (pkC * pkA % P % Q)/h`
- `s = r`

Lastly, since we modified Harry's generator we need to adapt Carlo's forgery: simply set `s = h*b + r` instead of `s = h + r`.

```haskell
Generators:
   Alice: (default)
   Carlo: pkA   -- pkA: Alice's public key
   b = (pkC * pkA % P % Q) / hA
   Harry: pkC^b -- pkC: Carlo's public key

Forge Carlo:
   g = pkC^b
   r = pkC
   s = hC*b + r

   g^v * pkC^w = pkC^{(hC*b + r)/s}
               = pkC^{(hC*b + r)/(hC*b + r)}
               = pkC
               = r

Forge Alice:
    g = pkC^b = pkA^{b*xC}
    r = hA*b = pkC * pkA % P % Q
    s = r

    g^v * pkA^w = pkA^{xC*v*b + w}
                = pkC^{hA*b/s} * pkA^{r/s}
                = pkC^{r/r} * pkA^{r/r}
                = pkC * pkA
                = r
```
And voilà!