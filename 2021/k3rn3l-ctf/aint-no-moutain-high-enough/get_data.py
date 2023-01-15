from pwn import remote, context
context.log_level = 'debug'

# Identity Matrix
msg = '\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01'

io = remote('ctf.k3rn3l4rmy.com', 2238)
io.sendlineafter('>> ', '3')
io.sendlineafter(' = ', msg)

for i in range(1, 6):
    io.sendlineafter('>> ', '2')
    io.sendlineafter(' = ', str(i))

    io.sendlineafter('>> ', '3')
    io.sendlineafter(' = ', msg)

io.interactive()