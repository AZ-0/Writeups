from pwn import remote
from math import gcd
from tqdm import tqdm

def to_base(n, b):
    repr = []
    while n:
        repr.append(n % b)
        n //= b
    
    return repr

base = (b'\1' + b'\0'*20).decode()
print(f'{base = }')

with open('save.txt', 'r') as file:
    commits = eval(file.read())

print('LOADED!')
print(f'{len(commits) = }')

def get_commit():
    io = remote('ctf.k3rn3l4rmy.com', 2232)
    io.sendline(base)
    io.recvuntil('commitment: ')
    commit = int(io.recvline())
    io.close()
    return commit

while 1:
    try:
        for i in tqdm(range(100)):
            try:
                commits.append(to_base(get_commit(), int.from_bytes(base.encode(), 'big')))
            except EOFError:
                pass

        with open('save.txt', 'w') as file:
            file.write(repr(commits))

    except Exception as e:
        print('='*200)
        print(e)
        print('='*200)
        continue

    print('='*200)

    flag = [gcd(*coeffs) for coeffs in zip(*commits)]
    with open('save.txt', 'w') as file:
        file.write(repr([flag]))

    print(flag)

    try:
        print(bytes(flag))
    except:
        pass
    else:
        break