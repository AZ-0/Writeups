from Crypto.Random.random import randrange
from Crypto.Util.number import getPrime

def generate(bits):
    p = getPrime(bits)
    x = randrange(p)
    g = randrange(2, p)
    y = pow(g,x,p)
    return p, g, x, y # y = g^x mod p

def sign(p, g, x, m):
    k = randrange(p)
    r = pow(g, k, p)
    inv_k = pow(k, -1, p - 1)
    s = ((m - x * r) * inv_k) % (p - 1)
    return r, s

def verify(p, g, y, m, r, s):
    if r <= 0 or r >= p - 1 or s < 0 or s >= p - 1:
        return False
    return pow(g, m, p) == ((pow(y, r, p) * pow(r, s, p)) % p)

print("Public key:")
p, g, x, y = generate(2048)
print(f"{p = }")
print(f"{g = }")
print(f"{y = }") # y = g^x mod p

try:
    print("Input a message.")
    m = int(input(">>> "))

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

# r = y
# s = (p-1) -y