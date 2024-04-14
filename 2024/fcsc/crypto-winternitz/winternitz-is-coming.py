import os
from ast import literal_eval
from hashlib import sha256

class WiC:

    def __init__(self, W = 257, msglen = 20, siglen = 40):
        # Parameters
        self.W = W
        self.msglen = msglen
        self.siglen = siglen

        self.n1 = self.siglen // 256 + 1 # = 1
        self.n2 = self.W // 256 + 1      # = 2

        # Evaluation points chosen uniformly at random
        self.Support = [
              8,  17,  26,  32,  52,  53,  57,  58,
             59,  63,  64,  66,  67,  71,  73,  76,
             79,  81, 111, 115, 132, 135, 141, 144,
            151, 157, 170, 176, 191, 192, 200, 201,
            202, 207, 216, 224, 228, 237, 241, 252,
        ]

        # Run key generation
        self._keygen()

    def _keygen(self):
        sk_seed = os.urandom(16)
        mask_seed = os.urandom(16)

        SK = [
            sha256(sk_seed + i.to_bytes(self.n1)).digest()
            for i in range(self.siglen)
        ]
        PK = SK.copy()
        for i in range(self.siglen):
            for j in range(1, self.W):
                PK[i] = self._H(PK[i], mask_seed, i, j)

        self.sk = (mask_seed, sk_seed)
        self.pk = (mask_seed, PK)

    def _byte_xor(self, b1, b2):
        assert len(b1) == len(b2), "Error: byte strings of different length."
        return bytes([x ^ y for x, y in zip(b1, b2)])

    def _encoding(self, msg):
        w = [0] * len(self.Support)
        for i in range(len(self.Support)):
            for j in range(len(msg)):
                # Constant coefficient is zero
                w[i] += msg[j] * self.Support[i] ** (j + 1)
            w[i] %= self.W
        return w

    def _H(self, s, m, i, j):
        return sha256(
            self._byte_xor(
                s,
                sha256(
                    m + i.to_bytes(self.n1) + j.to_bytes(self.n2)
                ).digest()
            )
        ).digest()

    def sign(self, message):
        if len(message) > self.msglen:
            print("Error: message too long.")
            return None

        mask_seed, sk_seed = self.sk

        w = self._encoding(message)
        S = [
            sha256(sk_seed + i.to_bytes(self.n1)).digest()
            for i in range(self.siglen)
        ]
        for i in range(self.siglen):
            for j in range(1, w[i] + 1):
                S[i] = self._H(S[i], mask_seed, i, j)

        return [s.hex() for s in S]

    # message is a list of bytes
    def verif(self, message, signature):
        if len(message) > self.msglen:
            print("Error: message too long.")
            return None

        mask_seed, PK = self.pk

        w = self._encoding(message)
        for i in range(self.siglen):
            for j in range(w[i] + 1, self.W):
                signature[i] = self._H(signature[i], mask_seed, i, j)

        return all(s == pk for s, pk in zip(signature, PK))

S = WiC()
pk = (
    S.pk[0].hex(),
    [ pk.hex() for pk in S.pk[1] ]
)

message = b"WINTERNITZ IS COMING"
signature = S.sign(message)

print(f"{message = }")
print(f"{signature = }")
print(f"{pk = }")

try:
    print("Input your message (hex format):")
    your_message = bytes.fromhex(input(">>> "))

    print("Input your signature (list of hex strings):")
    your_signature = literal_eval(input(">>> "))
    your_signature = [bytes.fromhex(s) for s in your_signature]

    assert message != your_message
    assert len(your_message) == 20
    assert len(your_signature) == 40

    if S.verif(your_message, your_signature):
        print("Congratulations! Here is your flag:")
        print(open("flag.txt").read())
    else:
        print("Not quite, try again!")

except:
    print("Please check your inputs.")
