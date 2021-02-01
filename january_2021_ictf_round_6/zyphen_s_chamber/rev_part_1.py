#####################
# FROM THE ORIGINAL #
#####################
MY_LUCKY_NUMBER = 736498

def geom(a,k,n):
    if k <= 2:
        return sum(a**i for i in range(k)) % n
    else:
        m = k//2
        b = pow(a,2,n)
        g = ((1+a)*geom(b,m,n))%n
        return g if k%2 == 0 else (g + pow(a,k-1,n))%n

def f(a,m,n):
    k = len(str(a))
    r = pow(10,k,n)
    return (a*geom(r,m,n))%n

def convert_to_ascii(text):
    return "".join(str(ord(char)) for char in text)


#######################
# REVERSE ENGINEERING #
#######################

#-----------------------------------#
#>- Linear Congruential Generator -<#
#-----------------------------------#

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


def lcg(m, a, b, seed, amount):
    values, num = [], seed
    for _ in range(amount):
        values.append(num)
        num = (a*num + b) % m
    return values


#-------------#
#>- Torture -<#
#-------------#

def rev_prepare(fresh):
    fresh[-1] -= MY_LUCKY_NUMBER*len(fresh)
    return [f ^ MY_LUCKY_NUMBER for f in fresh]


def retrieve_random_values(treasure, plaintext):
    values = []

    for c, p in zip(treasure, map(ord, plaintext)):
        assert c % p == 0 # ensures our method of doing this is right
        values.append(c // p)

    return values


def rev_torture(treasure, plaintext, m, a, b, seed):
    random_nums = lcg(m, a, b, seed, len(treasure))

    plaintext = []
    for t, r in zip(treasure, random_nums):
        assert t % r == 0 # once again, ensures it works: failing here means retrieving the modulus m of the LCG didn't work; changing to another output should do the trick
        plaintext.append(t // r)

    return ''.join(map(chr, plaintext))


#----------#
#>- MAIN -<#
#----------#

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


if __name__ == '__main__':
    rev()
