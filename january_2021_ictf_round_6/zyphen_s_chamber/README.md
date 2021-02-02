# ICTF ─ Round 6: Zyphen's Chamber

### Description
Welcome to my room... my murder room. This challenge should be easy, but frustrating, however, if you fail, there will be consequences. Your inevitable suffering. However, there is one way out. Solve this puzzle and maybe you will find a way. Good luck >:)... **P.S. Don't mind the voices you hear**

### Attachments
`ncat 52.201.238.52 3000`

[zyphenchamber.py](zyphenchamber.py)

### Category
Reversing/Crypto

### Points
250

## Part 1
As always, let's have a quick look into the tcp service to see what happens before starting anything. When we connect, it throws a bunch of things out:
```
Ciphertext: [<really big number>, <big number>, <big number>, ..., <big number>]
N: <big number>
E: <big number>
```
> Because there were too many numbers, [here](server_generated_output.txt) is the full output.


`N` and `E` hint toward RSA, we can keep that in mind and proceed with the reverse :D

First opening the file... bloody hell! (not even referencing Zyphen's questionable taste)

What to begin with?
A nice reflex to have when you must reverse something like *that*, is to sort things out a little before even starting anything else.


### Sorting things out

So here we go, picked up the code lying around and put it in a `main` function:

```python
def main():
    print(image)
    blood = hide_evidence()
    saliva = hide_evidence()
    bcleaner = blood * (MY_LUCKY_NUMBER - 736000) - 1
    scleaner = saliva * (MY_LUCKY_NUMBER - 736000) - 1

    while not (ripe_numbers(bcleaner)):
        blood = hide_evidence()
        bcleaner = blood * (MY_LUCKY_NUMBER - 736000) - 1

    while not (ripe_numbers(scleaner)):
        saliva = hide_evidence()
        scleaner = saliva * (MY_LUCKY_NUMBER - 736000) - 1

    u, v = wots_this(bcleaner, scleaner)
    rf = int(convert_to_ascii("PLEASEHELPMEINEEDTOGETOUT"))
    modman = f(rf, u[1], u[0])

    caesar = str(torture("*DONT TRUST THE E*... shut up " + reverse(FUNROOM), modman))

    print("Ciphertext: " + caesar)
    print("N: " + str(u[0]))
    print("E: " + str(u[1]))
```

I took the liberty of uppercasing constants and removing the code after `inputkey` ─ seeing as it is unrelated whatsoever with what happens before, so let's drop it for now and concentrate on the first step.

Most likely we will try to retrieve the content of funroom!

Perhaps `wots_this` generates keys? (actually, it does). But an interesting thing to notice is that we don't need to reverse `wots_this` because we know it's results and funroom doesn't matter here, nor do we need to reverse `f` at all since we know all it's parameters (but if you are as stupid as me you reverse them both anyway lol). That means we know `modman` as well.

So sorting things out told us that we only need to reverse what's in `torture`. Pretty neat, isn't it?


### `torture`'s reversal

```python
def torture(meat, blood):
    baked = splatter(meat, blood)
    treasure = []
    for i in range(len(baked)):
        treasure.append(ord(meat[i]) * baked[i])
    
    treasure = prepare(treasure)
    return treasure
```

Would you look at this, a whole bunch of new functions! First things first, we need to reverse `prepare`.


### `prepare`'s reversal

```python
def prepare(meat):
    fresh = []
    for i in range(len(meat)):
        fresh.append(meat[i]^MY_LUCKY_NUMBER)

    for k in range(len(fresh)):
        fresh[i] += MY_LUCKY_NUMBER

    return fresh
```

You might notice in the second for loop `i` is used instead of `k`. Because of python's quirky way of managing scopes, `i` is the last value it took in the first for loop, ie `len(meat) - 1`.
That means that the second for loop is equivalent to the following ─ since `fresh` has the same length as `meat`.
```python
fresh[-1] += MY_LUCKY_NUMBER*len(fresh)
```
Also, we can rewrite the first for loop in simpler code:
```python
fresh = [m ^ MY_LUCKY_NUMBER for m in meat]
```

Very well, we can now reverse the `prepare` function:
```python
def rev_prepare(fresh):
    fresh[-1] -= MY_LUCKY_NUMBER*len(fresh)
    return [f ^ MY_LUCKY_NUMBER for f in fresh]
```

This works because `a ^ b = c` is equivalent to `a ^ c = b`, thanks xor properties for that.

Back to `torture`! Oh wait, we have another function to reverse first.


### `splatter`'s reversal

Okay, the ascii values of the chars in `funroom` ─ here `meat` ─ are multiplied by some things in `baked`. Let's reverse `splatter`!
```python
def splatter(meat, seed):
    mess, num = [seed], seed

    a = hide_evidence()
    b = hide_evidence()
    m = hide_evidence()

    for _ in meat:
        num = (num*a + b) % m
        mess.append(a)

    return mess
```
(renamed for your convenience)

A quick look in `hide_evidence` tells us it outputs some random number.
Houston... we have a problem. How are we even supposed to reverse this when there are random numbers everywhere?!

As it turns out, there were two ways which I know of, we'll go over one of them:

In fact, `splatter` is a very well known and very not secure way of generating random numbers. Lo and behold, Linear Congruential Generators! [This post]() kindly explains us some maths needed to crack an LCG with only a little more than 10 values. Here's a python implementation for your beautiful eyes:

```python
def crack_lcg(values: list) -> tuple:
    from math import gcd
    s, t = values, []

    for i in range(len(s) -1):
        t.append(s[i+1] - s[i])

    u = lambda n: t[n+2]*t[n] - t[n+1]**2
    m = gcd(u(0), u(1))

    for i in range(len(t) -2):
        m = gcd(m, u(i))

    # the more values you provide at the start, the higher the probability of finding m is.

    a = t[1] * pow(t[0], -1, m) % m
    b = s[1] - a*s[0]

    return m, a, b % m
```

You might wonder, however, where the heck we are gonna find values to crack the LCG! Don't worry, Zyphen provided us some plaintext at this line:
```python
caesar = str(torture("*DONT TRUST THE E*... shut up " + reverse(FUNROOM), modman))
```

We know the message begins with `"*DONT TRUST THE E*... shut up "`, yahoo!
You might have forgotten what `torture` is at this point so here it is:
```python
def torture(meat, blood):
    baked = splatter(meat, blood)
    treasure = []
    for i in range(len(baked)):
        treasure.append(ord(meat[i]) * baked[i])
    
    treasure = prepare(treasure)
    return treasure
```

We can retrieve the first 30 values of the LCG by dividing the numbers in `treasure` before preparation with the ascii values in our plaintext. When we only needed 12 or so!

```python
def retrieve_random_values(treasure, plaintext):
    values = []

    for c, p in zip(treasure, map(ord, plaintext)):
        assert c % p == 0 # ensures our method of doing this is right
        values.append(c // p)

    return values
```


Then we only need to reenact the LCG with the values we found in order to completely and successfully retrieve funroom!
```python
def lcg(m, a, b, seed, amount):
    values, num = [], seed
    for _ in range(amount):
        values.append(num)
        num = (a*num + b) % m
    return values


def rev_torture(treasure, plaintext, m, a, b, seed):
    random_nums = lcg(m, a, b, seed, len(treasure))

    plaintext = []
    for t, r in zip(treasure, random_nums):
        assert t % r == 0 # once again, ensures it works: failing here means retrieving the modulus m of the LCG didn't work; changing to another output should do the trick
        plaintext.append(t // r)

    return ''.join(map(chr, plaintext))


def rev():
    PLAINTEXT = "*DONT TRUST THE E*... shut up "
    CIPHERTEXT = [...]

    treasure = rev_prepare(CIPHERTEXT)
    random_nums = retrieve_random_values(treasure, plaintext)
    m, a, b = crack_lcg(random_nums)

    plaintext = rev_torture(treasure, PLAINTEXT, m, a, b, random_nums[0])
    print(*reverse(plaintext[len(PLAINTEXT):]), sep='')
```

Sure enough, it works locally with [generated output](locally_generated_output.txt)!
We didn't even need `N` and `E` in the end, neat.


Let's move on to the [server's output](server_generated_output.txt)... Uh? It doesn't work?! Why?!


## The second coming of First Step

Only later was I told that on the server a piece of text was put right before our beloved plaintext.
A quick dirty script using the `assert` from `retrieve_random_values` does the trick:
```python
for _ in range(len(CIPHERTEXT)):
    try:
        random_nums = retrieve_random_values(treasure, PLAINTEXT)
    except AssertionError:
        treasure = treasure[1:]
        continue

    break
```

Here's the completed `rev` function!
```python
def rev():
    PLAINTEXT = "*DONT TRUST THE E*... shut up"
    CIPHERTEXT = [...]

    treasure = rev_prepare(CIPHERTEXT)
    for _ in range(len(CIPHERTEXT)):
        try:
            random_nums = retrieve_random_values(treasure, PLAINTEXT)
        except AssertionError:
            treasure = treasure[1:]
            continue

        break

    m, a, b = crack_lcg(random_nums)

    plaintext = rev_torture(treasure, PLAINTEXT, m, a, b, random_nums[0])
    print(*reversed(plaintext[len(PLAINTEXT):]), sep='')
```

The full script for part 1 is provided [here](rev_part_1.py)

> If you want to know the message that was put before our plaintext, you only need to make the LCG go backward ─ it works if gcd(a, m) = 1, which is actually frequent enough that a few tries to regenerate the server output fulfill this condition.


Our pretty little script outputs this pretty little base64:
```http
MDAxMTAxMTAwMDExMTAwMDAwMTEwMTExMDAxMTAxMDAwMDExMDExMTAwMTEwMTAwMDAxMTAxMTEwMDExMDAwMDAwMTEwMTExMDAxMTAwMTEwMDExMDAxMTAxMDAwMDAxMDAxMTAwMTAwMTAwMDExMDAwMTEwMDEwMDEwMDAxMTAwMDExMDExMDAwMTEwMTEwMDAxMTAxMTAwMDExMDEwMDAwMTEwMTEwMDEwMDAxMTAwMDExMDExMTAwMTEwMTExMDAxMTAxMTAwMTAwMDEwMTAwMTEwMTEwMDEwMDAwMTEwMDExMDAxMDAxMDAwMTAxMDAxMTAxMTAwMDExMDExMTAwMTEwMTEwMDAxMTAwMDEwMDExMDAxMDAxMDAwMTEwMDAxMTAwMTEwMDExMDEwMDAwMTEwMDExMDAxMTAxMTEwMDExMDAxMTAwMTEwMDAwMDAxMTAxMDAwMDExMDAxMTAwMTEwMTAwMDAxMTAwMDEwMDExMDEwMDAwMTEwMTEwMDAxMTAxMDAwMDExMDEwMDAwMTEwMTAwMDAxMTAwMDEwMDExMDEwMDAwMTEwMTAwMDAxMTAxMDAwMDExMDAxMQ==
```

Throw it into cyberchef, click on the magic wand, and... here we go!
```http
https://fdownl.ga/470CAFDADC
```

Oh, god, FINALLY. Step 2, here we are!

## Part 2, aka the easy step (lol)

The link from step 1 gets us a file, [`flag.txt`](flag.txt):
```diff
========================RSA MESSAGE START========================
eAvbw2LdhegM7oCmraCw3C6laNNgKnuTppBb/ZVDe6q9m2TDuezHY9rrleokopkDj7AR/62MHvravH4KfdsFXZAh60XhziwHrAEfTrqzsZ4OUsWpAWSsGssMUuMsKhABN/uGCn82dP3rrp+SeaYBguI3uvFlkbKAZOus79DaDnBaSPWVHL73oO28Y08b1baeYWYSLufdRffd6lEYpVaaQtrzk7+hGErdYVtRlzsJgkmhA7pjMCTSpRrgQJbb8AXOnC8YBvft7vePzPm/9sVNzzfHYH+psQYa94M5yHFTz4tcyqJphJZnHd2Xf6U4+7/N5kXzSpvl/4otjlReg53UBXExjYd3E7ZODJqtzxDE3ReWG5xjJlO3iNARSpa5LFjt5HufBMA6BVHG4O8LJRoVpdJdduUUVBVItXRJ5E+GqfUkhmgCFDuzjEAsZtayPVcn+PmH4Db6pZ6T4eqZf1Ywe6jrAJCHJW5BHBXoMLTT7WXdkSlAvEEXi2+UErj5oEWpKVknaQtfbarEprXPNC8fDoHwtldWQh6FYNotKSuO+5juC3B0NEsZvAxrynAY0rHUwJTAB9YxY8pi7WODkiShtDT2bOrl6jXZCVKKyl81FhQ+1rrXSzk/BFY/2I2MxhJyyLCfVWVF+LjATH93AhBfgT9cgifwkKrTLii6vHiaFvw=
========================RSA MESSAGE END ========================
n=MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAiRQeIeddRZcBD8oM5Z5w+LXcOrBK78ZONSd1QxDZwbEs43RQb4O3ugKjYst7RTwSu/rPhZ3Pwd9oaCxriMQWFuNlVsx/GDUViMUrgFf4+9a6uxJm3IQ7efoibbYDu4omtYKfRKSU+L57JYOKLAgH9WKSMWjsQXx7c7qamzC6Kr0lBo4zn0d9ok11z6uzXsvJrVPFwTJMrL1QTJIvfAVn/CywYM3q9ptfrg4LBbMhcBGlV/T9k9ZWVB3nB5fKasgkVOFSGLWQkZ3XfutokcElBt21Vq2esn7rQf9VnDQ/qS1hyqTTGsROQiYAWpSDk/pVw9dN5DHoRxMiuTIC07u5aOp+6hioGwEVAYuGnEQ2CDAwXuI+c0GIfe4N8VAaeWOT2yte7ZcHl5jf0aN5XKgAUwshrUScYbYCZ3ba7CheCRMlYcXLDhDhZtQ2E45oV82TfOUTe/TE5TFQz5znOoVu8Cp2+7jaLK/hBWO5KiwVDQnEV9jnmOS3iqCunkeS1zfgEQ3fT6D6f4NmOS++hlLF4JiPQU1MeAxrFW5JazmQ8XMYHRN329MdvfS+z60sD9xE6ugjLv0AyozgWe83wiKyLQIWZVl81B55IrR+gAwuysIZ4qE0EWUqzBQW5v2Y6VxPGhXwC+ZwVM9X1SV95WNKNDdaPdQClLMUtDBtvpOb+v8CAwEAAQ==

e = 452830202329312f76521c7e3d182629670c247d3f67606a0d7e181064160d0d7260171e000170067a29
```

Huhu, RSA it is. First things first:
* e is clearly not a standard value (usually 3, 7, some small prime, or 65537)
* n is base64

When you get base64, you throw it into cyberchef and click on the magic wand... Wait, wat?! Certificate file detected? Cyberchef rocks!

There are many ways to extract a certificate; I dumped into a file and got openssl to read it:

```python
from base64 import b64decode

n = b64decode(r'<base64 here>')
with open('n.crt', 'wb') as file:
    file.write(n)
```

`openssl rsa -in n.crt -inform DER -pubin -modulus -text`

```python
Modulus: 0x89141E21E75D4597010FCA0CE59E70F8B5DC3AB04AEFC64E3527754310D9C1B12CE374506F83B7BA02A362CB7B453C12BBFACF859DCFC1DF68682C6B88C41616E36556CC7F18351588C52B8057F8FBD6BABB1266DC843B79FA226DB603BB8A26B5829F44A494F8BE7B25838A2C0807F562923168EC417C7B73BA9A9B30BA2ABD25068E339F477DA24D75CFABB35ECBC9AD53C5C1324CACBD504C922F7C0567FC2CB060CDEAF69B5FAE0E0B05B3217011A557F4FD93D656541DE70797CA6AC82454E15218B590919DD77EEB6891C12506DDB556AD9EB27EEB41FF559C343FA92D61CAA4D31AC44E4226005A948393FA55C3D74DE431E8471322B93202D3BBB968EA7EEA18A81B0115018B869C44360830305EE23E7341887DEE0DF1501A796393DB2B5EED97079798DFD1A3795CA800530B21AD449C61B6026776DAEC285E09132561C5CB0E10E166D436138E6857CD937CE5137BF4C4E53150CF9CE73A856EF02A76FBB8DA2CAFE10563B92A2C150D09C457D8E798E4B78AA0AE9E4792D737E0110DDF4FA0FA7F8366392FBE8652C5E0988F414D4C780C6B156E496B3990F173181D1377DBD31DBDF4BECFAD2C0FDC44EAE8232EFD00CA8CE059EF37C222B22D021665597CD41E7922B47E800C2ECAC219E2A13411652ACC1416E6FD98E95C4F1A15F00BE67054CF57D5257DE5634A34375A3DD40294B314B4306DBE939BFAFF
Exponent:
65537
```

So... the exponent is `65537`? Isn't that a public key?
Let's try it anyway, there's nothing to lose after all.

> Trying things anyway is a good ctf mindset that I didn't have, wasting a day and a night ─ solved this step in a much more complicated way than shown here.
This step actually stumped many people who knew about RSA, because 65537 is so widely used as a public key that decrypting with it got completely out of our minds. Well done, Zyphen.

```py
from base64 import b64decode

c = b64decode(r'<base64 here>')
n = <modulus here>
p = pow(int.from_bytes(c, 'big'), 65537, n)

print(hex(p))
```
```python
0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00696374667b746831735f31735f7468335f6b33792e2e2e44305f5930555f483334525f5448334d3f7d
```

I say, so many `ff` look like no use to me. Throwing `00696374667b746831735f31735f7468335f6b33792e2e2e44305f5930555f483334525f5448334d3f7d` into cyberchef, we get:
```
.ictf{th1s_1s_th3_k3y...D0_Y0U_H34R_TH3M?}
```

YEAH! Let's submit the flag! Wait, this isn't the flag. In fact, we just got the masterkey to start step 2...

## Road to the flag!

So what does the server tell us?
```http
[...]
What is the key? ictf{th1s_1s_th3_k3y...D0_Y0U_H34R_TH3M?}
You got out of your room?! Impossible! I guess use your compensation... Maybe I will be back, but you aren't done yet... QUICK WHAT IS THE FLAG
x = 4974576F756C64426546756E6E794966596F754469644465636F6465546869734D65737361676542757449446F6E744B6E6F77576879536F4C657473426553686F7274416E6453696D706C6550574E4973436F6D696E67536F6F6E46726F6D596F7572735472756C795374617274696E6745617379456E64696E6748617264
z = 4974576f756c64426546756e6e794966596f754469644465636f6465546869734d65737361676542757449446f6e744b6e6f77576879536f4c657473426553686f7274416e6453696d706c6550574e4973436f6d696e371f2a2e3d033a2a21093a262b3c0133272936062632332220213512243d3c002a302629221c2e2730
What is the key?!?!?!?!?!??!
Wrongggg and toooooo slow!!! Did you really think you were any good at crypto? >:) >:) Time for your pain and suffering!!
```

Interesting. Perhaps the relevant code will help us understand better:
```python
def main():
    from random import choice
    xecrets = ["[REDACTED]", "[REDACTED]", "[REDACTED]"]
    answers = ["[REDACTED]", "[REDACTED]", "[REDACTED]"]

    x = choice(xecrets)
    a = choice(answers[a])
    z = two_str(a, str(x))

    check = bytes.fromhex(a.lstrip('0x')).decode('ASCII')

    if input("What is the key? ") == masterkey:
        print("You got out of your room?! Impossible! I guess use your compensation... Maybe I will be back, but you aren't done yet... QUICK WHAT IS THE FLAG")

        print(f"x = {x}\nz = {str(z)[2:]}")

        if input("What is the key?!?!?!?!?!??! ") == check:
            print(2*"\n" + flag)
        else:
            print("\nWrongggg and toooooo slow!!! Did you really think you were any good at crypto? >:) >:) Time for your pain and suffering!!")   

    else:
        print("\nTime for your pain and suffering!!")
```
> I renamed things a bit, tidied things a bit. It helps :D

It looks like the only thing we need to do is reversing that `two_str` function! Neat.
```python
def hexify(str):
    return int(str,base=16)

def two_str(str1,str2):
    a = hexify(str1)
    b = hexify(str2)
    return hex(a ^ b)
```

And we're done. two_str is an xor, and the xor has this ever so tiny but really important property that:
`x ^ a = z <=> x ^ z = a`

So we can reverse this function by itself!
```python
def rev_check(x, z):
    a = two_str(x, z)
    return bytes.fromhex(a.lstrip('0x')).decode('ASCII')
```

In the original code for the `main` function there is a timeout (I removed it for readability), which means we'll need to connect to tcp, scrap `x` and `z`, then return the values.
Since it's not really reversing here's the completed code:
```python
def rev_check(x, z):
    a = two_str(x, z)
    return bytes.fromhex(a.lstrip('0x')).decode('ASCII')

def solve():
    from pwn import remote
    r = remote(HOST, PORT)

    # MASTERKEY
    r.recvuntil('What is the key? ')
    r.sendline(MASTERKEY)
    print('What is the key?', MASTERKEY)

    # X AND Z
    print(r.recvuntil('= ').decode(), end='')
    print(x := r.recvline(keepends=False).decode())
    print(r.recvuntil('= ').decode(), end='')
    print(z := r.recvline(keepends=False).decode())

    # LAST CHECK
    check = rev_check(x, z)
    r.sendline(check)
    print(r.recvuntil('?!?!??! ').decode(), check)

    # FLAG
    print(r.recvall().decode(), end='')


if __name__ == '__main__':
    solve()
```
```http
What is the key? ictf{th1s_1s_th3_k3y...D0_Y0U_H34R_TH3M?}
You got out of your room?! Impossible! I guess use your compensation... Maybe I will be back, but you aren't done yet... QUICK WHAT IS THE FLAG
x = 49414D4E4F544845524549414D4E4F544845524549414D4E4F544845524549414D4E4F544845524549414D4E4F544845524549414D4E4F544845524549414D4E4F544845524549414D4E4F544845524549414D4E4F544845524549414D4E4F544845524549414D4E4F544845524549414D4E4F544845524549414D4E4F544845524549414D4E4F544845524549414D4E4F5448455245 
 z = 49414d4e4f544845524549414d4e4f544845524549414d4e4f544845524549414d4e4f544845524549414d4e4f544845524549414d4e4f544845524549414d4e4f544845524549414d4e4f544845524549414d4e4f544845524549414d4e4f544845524549414d4e4f5448455245494108000b19111607030f041f0701130106130b1d150c050a1d1c041c1c040e1f0b1f180d040100
What is the key?!?!?!?!?!??!  ENDMYSUFFERINGICANTTAKEITANYMOREPLEASE

ictf{1_D0N7_KN0W_WH0_W3_4R3_H3LP_M3_W3_4R3_SUFF3R1NG...C0NGR47S_0N_7H3_CH4ALL3NG3_D0N7_M1ND_7H47_V01C3}
```
All hail pwntools!
[Here](rev_part_2.py) is the full script :D

Thanks for reading!

## Easter Egg ─ Addendum by Chopswiss
Remember our plaintext `*DONT TRUST THE E*`?

In flag.txt he value e is `452830202329312f76521c7e3d182629670c247d3f67606a0d7e181064160d0d7260171e000170067a29`
Decrypted key is `00696374667b746831735f31735f7468335f6b33792e2e2e44305f5930555f483334525f5448334d3f7d` (`ictf{th1s_1s_th3_k3y...D0_Y0U_H34R_TH3M?}`)

So if you then XOR both you get `EASTEREGG!CONGRATSONFINDINGITCREATEATICKET`.
