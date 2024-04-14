from Crypto.Random.random import randrange
from Crypto.Util.number import getPrime

def generate(bits):
    p = 2
    while p % 4 != 1:
        p = getPrime(bits) # p = 1 mod 4 <=> -1 est un carré mod p
    x = randrange(p)
    g = 2
    y = pow(g, x, p)
    return p, g, x, y

def sign(p, g, x, m):
    k = randrange(p)
    r = pow(g, k, p)
    inv_k = pow(k, -1, p - 1)
    s = ((m - x * r) * inv_k) % (p - 1)
    return r, s

def verify(p, g, y, m, r, s):
    if r <= 0 or r >= p or s < 0 or s >= p - 1:
        return False
    return pow(g, m, p) == ((pow(y, r, p) * pow(r, s, p)) % p)

# r = g^t
# y^r * r^s = g^(g^t x + t s)


# t = (p-1)/4
# r = g^(t-2) = (p-1)/4 mod p

# m = r log y + s log r = 0 + s(t-2)
# s = m/(t-2)


print("Public key:")
p, g, x, y = generate(2048)
print(f'DEBUG | x % 4 is {x%4}')
print(f"{p = }")
print(f"{g = }")
print(f"{y = }")

try:
    m = randrange(p)
    print(f"Your task is to sign the following message m = {m}")

    print("Input a signature. First, input r.")
    r = int(input(">>> "))

    print("Now, input s.")
    s = int(input(">>> "))

    if verify(p, g, y, m, r, s):
        print("Congratulations! The message and signature match. Here is your flag:")
        print(open("flag.txt").read())
    else:
        print("Better luck next time!")
except:
    print("Please check your inputs!")
