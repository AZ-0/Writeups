#####################
# FROM THE ORIGINAL #
#####################

def hexify(str):
    return int(str,base=16)

def two_str(str1,str2):
    a = hexify(str1)
    b = hexify(str2)
    return hex(a ^ b)


#######################
# REVERSE ENGINEERING #
#######################

HOST, PORT = '100.24.46.36', 3000
MASTERKEY = 'ictf{th1s_1s_th3_k3y...D0_Y0U_H34R_TH3M?}'

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
