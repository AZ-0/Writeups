from pwn import remote, context
from ast import literal_eval
from functools import reduce
from operator import xor

def option(n):
    io.sendlineafter('>> ', str(n))

def oracle(x: int) -> int:
    option(1)
    io.sendlineafter('>> ', str((x, 0)))
    io.recvuntil('comes: ')
    return int(io.recvline())

def read_tuple() -> tuple[int, int]:
    return literal_eval(io.recvline(False)[1:].strip().decode())

SHOOT_DIC = {
    0  : [[0,1],[0,2],[0,3],[0,4],[0,5],[0,6],[0,7],[0,8],[0,9]],
    1  : [[1,0],[1,1],[1,2],[1,3],[1,4],[1,5],[1,6],[1,7],[1,8],[1,9],[1,10]],
    2  : [[2,0],[2,1],[2,2],[2,3],[2,4],[2,5],[2,6],[2,7],[2,8],[2,9],[2,10]],
    3  : [[3,0],[3,1],[3,2],[3,3],[3,4],[3,5],[3,6],[3,7],[3,8],[3,9],[3,10]],
    4  : [[4,0],[4,1],[4,2],[4,3],[4,4],[4,5],[4,6],[4,7],[4,8],[4,9],[4,10]],
    5  : [[5,1],[5,2],[5,3],[5,4],[5,5],[5,6],[5,7],[5,8],[5,9]],
    6  : [[1,0],[2,0],[2,1],[3,1],[3,2],[4,2],[4,3],[5,3],[5,4]],
    7  : [[0,1],[1,1],[1,2],[2,2],[2,3],[3,3],[3,4],[4,4],[4,5],[5,5],[5,6]],
    8  : [[0,2],[0,3],[1,3],[1,4],[2,4],[2,5],[3,5],[3,6],[4,6],[4,7],[5,7],[5,8]],
    9  : [[0,4],[0,5],[1,5],[1,6],[2,6],[2,7],[3,7],[3,8],[4,8],[4,9],[5,9]],
    10 : [[0,6],[0,7],[1,7],[1,8],[2,8],[2,9],[3,9],[3,10],[4,10]],
    11 : [[0,4],[0,3],[1,3],[1,2],[2,2],[2,1],[3,1],[3,0],[4,0]],
    12 : [[0,6],[0,5],[1,5],[1,4],[2,4],[2,3],[3,3],[3,2],[4,2],[4,1],[5,1]],
    13 : [[0,8],[0,7],[1,7],[1,6],[2,6],[2,5],[3,5],[3,4],[4,4],[4,3],[5,3],[5,2]],
    14 : [[0,9],[1,9],[1,8],[2,8],[2,7],[3,7],[3,6],[4,6],[4,5],[5,5],[5,4]],
    15 : [[1,10],[2,10],[2,9],[3,9],[3,8],[4,8],[4,7],[5,7],[5,6]]
}

class PandorasComb:
    def __init__(self,key_62):
        if type(key_62) == str:
            key_62 = bytes.fromhex(key_62)

        self.key = list(key_62)
        self.state = [
            [' '] + self.key[:9] + [' '],
            self.key[9:20],
            self.key[20:31],
            self.key[31:42],
            self.key[42:53],
            [' '] + self.key[53:] + [' ']
        ]

    def shoot(self, indir, ray, verbose=False):
        if indir > 15:
            indir %= 16
            path = SHOOT_DIC[indir]
            for i in range(len(SHOOT_DIC[indir])):
                ray ^= self.state[path[-(i+1)][0]][path[-(i+1)][1]]
                self.state[path[-(i+1)][0]][path[-(i+1)][1]] = ray

        else:
            path = SHOOT_DIC[indir]
            for x, y in path:
                ray ^= self.state[x][y]
                self.state[x][y] = ray

        if verbose:
            print(self.state)

        return ray

def recover_ray11(indir: int) -> list:
    for _ in range(5):
        oracle(indir)

    acik = oracle(indir)
    bcjk = oracle(indir)
    ck = oracle(indir)
    defghijk = oracle(indir)
    egik = oracle(indir)
    fgjk = oracle(indir)
    gk = oracle(indir)
    hijk = oracle(indir)
    ik = oracle(indir)
    jk = oracle(indir)
    k = oracle(indir)

    j = jk ^ k
    i = ik ^ k
    h = hijk ^ i ^ j ^ k
    g = gk ^ k
    f = fgjk ^ g ^ j ^ k
    e = egik ^ g ^ i ^ k
    d = defghijk ^ e ^ f ^ g ^ h ^ i ^ j ^ k
    c = ck ^ k
    b = bcjk ^ c ^ j ^ k
    a = acik ^ c ^ i ^ k

    return [a, b, c, d, e, f, g, h, i, j, k]


def recover_ray(x: int) -> list[int]:
    ray = recover_ray11(x)
    if 0 < x < 5:
        return ray
    return ray[2:]

def recover_comb() -> PandorasComb:
    key = []
    for x in range(6):
        key.extend(recover_ray(x))
    return PandorasComb(key)

def recover_flag(comb: PandorasComb):
    print('='*200)

    dirs = [read_tuple() for _ in range(57)]

    flag = []
    for indir, res in dirs:
        path = SHOOT_DIC[indir]
        f = res ^ reduce(xor, [comb.state[x][y] for x, y in path])
        print(chr(f), end='')

        flag.append(f)
        comb.shoot(indir, f)

    print()
    print('='*200)
    return flag

if __name__ == '__main__':
    context.log_level = 'debug'
    io = remote('ctf.k3rn3l4rmy.com', 2239)

    print('Recovering comb...')
    comb = recover_comb()

    option(2)
    io.recvuntil("nothing...")
    io.recvline()
    io.recvline()
    print(''.join(map(chr, recover_flag(comb))))

    io.close()