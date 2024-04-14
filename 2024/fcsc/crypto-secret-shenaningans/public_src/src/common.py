# Secure channel implementation: common primitives

import os
import sys
import logging
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

## Commands
CMD_STRING_VERSION             = b"\x00"
CMD_KEXDH_INIT                 = b"\x01"
CMD_KEXDH_REPLY                = b"\x02"
CMD_NEWKEYS                    = b"\x03"
CMD_IGNORE                     = b"\x04"
CMD_PING                       = b"\x05"
CMD_PONG                       = b"\x06"
CMD_DISABLE_SC                 = b"\x07"
CMD_SC_SERVER_ADDITIONAL_INFO  = b"\x08"
CMD_GET_FLAG                   = b"\x09"

## Logging class
class CustomFormatter(logging.Formatter):
    CYAN = '\033[36m'
    YELLOW = '\033[33;20m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    RESET = '\033[0m'
    FORMAT = "[%(asctime)s] - %(message)s"

    FORMATS = {
        logging.DEBUG:      PURPLE + FORMAT + RESET, # DEBUG
        logging.INFO:       CYAN + FORMAT + RESET, # Server
        logging.WARNING:    YELLOW + FORMAT + RESET, # Client
        logging.ERROR:      RED + FORMAT + RESET, # Sniffer and Error
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Get verbose mode
debug = os.getenv("DEBUG", default=1)

logger = logging.getLogger()
if debug == 0:
    logger.setLevel(logging.CRITICAL)
else:
    logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
if debug == 0:
    ch.setLevel(logging.CRITICAL)
else:
    ch.setLevel(logging.DEBUG) 
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)

def thread_exit():
    sys.exit(-1)

#### Key exchange for secure channel establishment primitives
def sign_key_exchange(data, private_key):
    h = SHA256.new(data)
    sig = DSS.new(private_key, encoding = 'binary', mode = 'fips-186-3').sign(h)
    return sig

def verify_key_exchange(data, public_key, sig):
    h = SHA256.new(data)
    try:
        DSS.new(public_key, encoding = 'binary', mode = 'fips-186-3').verify(h, sig)
        return True
    except:
        return False

def ECDH_gen_ephemeral_private_key():
    # Ephemeral private keys are secret scalars for the NIST curve
    key = ECC.generate(curve = 'P-256')
    return key.d.to_bytes()

def ECDH_gen_public_data(private_x):
    # Scalar multiplication of the generator on the curve
    G = ECC.EccPoint(
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        curve = 'P-256'
    )
    P = int.from_bytes(private_x, byteorder = 'big') * G
    P_ = ECC.construct(curve = 'P-256', point_x = P.x, point_y = P.y)
    return P_.public_key().export_key(format = 'raw', compress = False)

def ECDH_gen_shared_secret(private_x, public_point_raw):
    # Scalar multiplication of the point
    try:
        P = ECC.import_key(public_point_raw, curve_name = 'P-256')
    except:
        print_err("[ERROR] Error in ECDH_gen_shared_secret ... Aborting!")
        thread_exit()
    Y = int.from_bytes(private_x, byteorder = 'big') * P.pointQ
    Y_ = ECC.construct(curve = 'P-256', point_x = Y.x, point_y = Y.y)
    h = SHA256.new()
    h.update(Y_.public_key().export_key(format = 'raw', compress = False))
    shared_secret = h.digest()
    return shared_secret

# Derive MAC and encryption keys from the shared secret for the secure channel given a diversifier (the "direction")
def derive_secure_channel_keys(diver, K):
    # Derive encryption key
    h = SHA256.new()
    h.update(diver + b"ENCRYPT" + K)
    kenc = h.digest()
    # Derive MAC key
    h = SHA256.new()
    h.update(diver + b"MAC" + K)
    kmac = h.digest()
    return kenc, kmac

#### Clear send and receive on the line primitives
## Send a command on the line in clear
def clear_send_packet(send, recv, cmd_type, payload, packet_counter):

    # Sanity check
    if len(payload) > 254:
        logger.error(f"[ERROR] Payload len {len(payload)} is too big...")
        thread_exit()

    cmd = cmd_type + payload
    cmd = len(cmd).to_bytes(1, 'big') + cmd
    send(cmd)
    return packet_counter + 1

## Receive a command on the line in clear
def clear_recv_packet(send, recv, packet_counter, expected_cmd = None):

    # Receive the command length
    packet_len = int.from_bytes(recv(1), byteorder = 'big')

    # Receive the rest
    packet = recv(packet_len)
    if len(packet) == 0:
        logger.error("[ERROR] Unexpected empty packet!")
        thread_exit()

    cmd = packet[:1]
    if expected_cmd is not None:
        if expected_cmd != cmd:
            logger.error(f"[ERROR] Unexpected command {expected_cmd} != {cmd}")
            thread_exit()

    payload = packet[1:]
    return cmd, payload, packet_counter + 1

#### Secure channel communication using Encrypt-then-MAC with established keys
def sc_send_packet(send, recv, cmd_type, payload, kenc, kmac, packet_counter, iv):

    # Get the padding to apply
    pad = AES.block_size - ((len(payload) + 2) % AES.block_size)
    payload = cmd_type + len(payload).to_bytes(1, byteorder = 'big') + payload + (pad * b'\x00')

    # Encrypt the padder payload
    cipher = AES.new(kenc, AES.MODE_CBC, iv=iv)
    payload = cipher.encrypt(payload)

    # Compute the HMAC on
    h = HMAC.new(kmac, digestmod = SHA256)
    if len(payload) + h.digest_size > 255:
        logger.error("[ERROR] Payload len is too big")
        thread_exit()

    prepend = (len(payload) + h.digest_size).to_bytes(1, byteorder = 'big')

    # Update with the implicit 64 bits packet counter
    h.update(packet_counter.to_bytes(8, byteorder = 'big'))

    # Update with the length
    h.update(prepend)
    h.update(payload)
    # Append the HMAC
    new_iv = payload[-AES.block_size:]
    payload = prepend + payload + h.digest()

    # Check the whole length
    if len(payload) > 255:
        logger.error(f"[ERROR] Payload len {len(payload)} is too big")
        thread_exit()

    send(payload)
    return packet_counter + 1, new_iv

def sc_recv_packet(send, recv, kenc, kmac, packet_counter, iv, expected_cmd = None):

    h = HMAC.new(kmac, digestmod = SHA256)

    # Receive the encrypted command length
    packet_len_byte = recv(1)
    packet_len = int.from_bytes(packet_len_byte, byteorder = 'big')

    # Receive the rest
    packet = recv(packet_len)

    # Packet should be at least MAC plus one block
    if len(packet) < (h.digest_size + AES.block_size):
        logger.error("[ERROR] Unexpected encrypted packet!")
        thread_exit()

    # Check the mac
    mac = packet[-h.digest_size:]
    enc_payload = packet[:-h.digest_size]
    new_iv = enc_payload[-AES.block_size:]

    # Update with length and packet counter
    h.update(packet_counter.to_bytes(8, byteorder = 'big'))
    h.update(packet_len_byte)
    h.update(enc_payload)
    hmac = h.digest()
    if hmac != mac:
        logger.error("[ERROR] Erroneous MAC in encrypted packet!")
        thread_exit()

    # MAC is OK, decrypt stuff
    cipher = AES.new(kenc, AES.MODE_CBC, iv = iv)
    payload = cipher.decrypt(enc_payload)
    if len(payload) < 2:
        logger.error("[ERROR] Erroneous payload size in encypted packet!")
        thread_exit()

    cmd = payload[0:1]
    if expected_cmd is not None:
        if expected_cmd != cmd:
            logger.error(f"[ERROR] Unexpected command {expected_cmd} != {cmd}")
            thread_exit()

    real_len = int.from_bytes(payload[1:2], 'big')
    if len(payload[2:]) < real_len:
        logger.error("[ERROR] Bad encrypted packet structure")
        thread_exit()

    payload = payload[2:2 + real_len]
    return cmd, payload, packet_counter + 1, new_iv
