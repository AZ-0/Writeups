import os
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class SSS:
    def __init__(self, secret, k):
        self.p = 931620319462745440509259849070939082848977
        self.k = k
        self.polynomial = [ int.from_bytes(secret) ]
        for _ in range(k):
            self.polynomial.append(int.from_bytes(os.urandom(16)))
        self.index = int.from_bytes(b"FCSC2024")

    def eval_poly(self,x):
        return sum(self.polynomial[j] * (x ** j) for j in range(self.k + 1)) % self.p

    def generate_share(self):
        self.index = self.index + 1
        return self.index, self.eval_poly(self.index)

if __name__ == "__main__":
    key  = os.urandom(16)
    iv   = os.urandom(16)
    flag = pad(open("flag.txt", "rb").read().strip(), AES.block_size)
    E    = AES.new(key, mode = AES.MODE_CBC, iv = iv)
    flag_enc = E.encrypt(flag)

    k = 16
    s = SSS(key, k)
    shares = [ s.generate_share() for _ in range(k) ]

    data = {
        "iv": iv.hex(),
        "flag_enc": flag_enc.hex(),
        "shares": shares,
    }
    print(json.dumps(data, indent = 4))
