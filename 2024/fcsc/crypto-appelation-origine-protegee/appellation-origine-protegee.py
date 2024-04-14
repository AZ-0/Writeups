from hashlib import sha256

class AOP:
    def __init__(self, s = 1):
        self.p = 18446744073709551557 # p - 1 not a multiple of 3
        self.t = 5
        self.r = 9
        self.RC = [
            [ int.from_bytes(sha256(b"FCSC2024#" + str(self.t*j + i).encode()).digest()) % self.p for i in range(self.t) ]
            for j in range(self.r)
        ]
        self.M = [
            [ pow(i, j, self.p) for i in range(1, self.t + 1) ]
            for j in range(self.t)
        ]

    def R(self, r):
        # self.S <- self.S * M
        s = [ 0 ] * self.t
        for j in range(self.t):
            acc = 0
            for i in range(self.t):
                s[j] += self.M[i][j] * self.S[i]
            s[j] %= self.p
        self.S = s[:]

        # self.S <- self.S + RC[i]
        for j in range(self.t):
            self.S[j] += self.RC[r][j]

        # self.S <- self.S ** e
        e = pow(3, -r, self.p - 1)
        self.S[0] = pow(self.S[0], e, self.p)
        print(f'r{r+1} = ', self.S[0])

    def __call__(self, L):
        assert len(L) == self.t, f"Error: input must be a list of {self.t} elements."
        assert all(x in range(0, self.p) for x in L), f"Error: elements must be in [0..{self.p - 1}]."
        self.S = L[:]
        for i in range(self.r):
            self.R(i)
        return self.S

if __name__ ==  "__main__":
        aop = AOP()

        print("Input your values as a comma-separated list: ")
        X = input(">>> ").split(",")
        X = [ int(x) for x in X ]
        Y = aop(X)
        print('X =', X)
        print('Y =', Y)
        if X[0] == 0 and Y[0] == 0:
            print('CONGRATs')
            flag = open("flag.txt").read()
            print(flag)
        else:
            print("Nope!")

