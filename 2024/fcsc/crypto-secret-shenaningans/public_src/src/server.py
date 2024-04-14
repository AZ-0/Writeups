#### Server implementation

from common import *

SERVER_VERSION_STRING = b"SERVER_V_1"
send_packet_counter = 0
recv_packet_counter = 0

# Load server private key
with open("data/server_private_key.der", "rb") as f:
    server_private_key = ECC.import_key(f.read())

# Load server public key
with open("data/server_public_key.der", "rb") as f:
    server_public_key_raw = f.read()

# Secure channel state
secure_channel = False
INITIAL_SEND_IV = b'\xaa' * 16
INITIAL_RECV_IV = b'\xbb' * 16

def main_server(send, recv):
    global send_packet_counter
    global recv_packet_counter
    global secure_channel

    logger.info("[SERVER] Spawning the server")

    ##### Exchange our version in clear
    send_packet_counter = clear_send_packet(send, recv, CMD_STRING_VERSION, SERVER_VERSION_STRING, send_packet_counter)
    cmd, client_version, recv_packet_counter = clear_recv_packet(send, recv, recv_packet_counter, expected_cmd=CMD_STRING_VERSION)
    logger.info(f"[SERVER] Received client version {client_version.decode()}")

    ##### Proceed with key exchange
    # Generate an ephemeral ECDH private key and the corresponding serialized point
    y = ECDH_gen_ephemeral_private_key()
    Gy = ECDH_gen_public_data(y)

    # Wait for something from the client
    while True:
        cmd, payload, recv_packet_counter = clear_recv_packet(send, recv, recv_packet_counter)
        if cmd == CMD_IGNORE:
            # In case of ignore command, well ignore and loop ...
            logger.info("[SERVER] CMD_IGNORE received")
            continue
        elif cmd == CMD_PING:
            # In case of "ping", respond with "pong" with the received payload and loop
            logger.info("[SERVER] CMD_PING received")
            send_packet_counter = clear_send_packet(send, recv, CMD_PONG, payload, send_packet_counter)
            continue
        elif cmd == CMD_KEXDH_INIT:
            # In case of key exchange init, this is it we have the data we have been waiting to continue
            # the key exchange
            logger.info("[SERVER] CMD_KEXDH_INIT received")
            break 
        else:
            # This is an unexpected command at this stage
            logger.error("[SERVER] Error in possible commands during key exchange. Aborting.")
            thread_exit()

    # Here, we compute the shared secret from CMD_KEXDH_INIT
    Gx = payload
    shared_secret = ECDH_gen_shared_secret(y, Gx)

    # Sign the whole key exchange and send the CMD_KEXDH_REPLY
    sig = sign_key_exchange(SERVER_VERSION_STRING + client_version + Gx + Gy + server_public_key_raw + shared_secret, server_private_key)
    payload_to_send = Gy + sig
    send_packet_counter = clear_send_packet(send, recv, CMD_KEXDH_REPLY, payload_to_send, send_packet_counter)

    # The only possible commands here are IGNORE or CMD_NEWKEYS (to ACK our secure channel) in clear. Everything else is an error.
    while True:
        cmd, payload, recv_packet_counter = clear_recv_packet(send, recv, recv_packet_counter)
        if cmd == CMD_IGNORE:
            # In case of ignore command, well ignore and loop ...
            logger.info("[SERVER] CMD_IGNORE received")
            continue
        elif cmd == CMD_NEWKEYS:
            # OK, we got to secure channel
            logger.info("[SERVER] CMD_NEWKEYS received")
            break
        else:
            # This is an unexpected command at this stage
            logger.error("[SERVER] Error in possible commands during key exchange. Aborting.")
            thread_exit()

    # ACK the secure channel establishement by sending CMD_NEWKEYS
    send_packet_counter = clear_send_packet(send, recv, CMD_NEWKEYS, b"", send_packet_counter)

    # Derive the secure channel keys
    kenc_recv, kmac_recv = derive_secure_channel_keys(b"CLIENTTOSERVER", shared_secret)
    kenc_send, kmac_send = derive_secure_channel_keys(b"SERVERTOCLIENT", shared_secret)

    # Set secure channel as active
    logger.info("[SERVER] Secure channel is ON!")
    secure_channel = True
    iv_recv = INITIAL_RECV_IV
    iv_send = INITIAL_SEND_IV

    # Send some sensitive configuration metadata in the secure channel
    send_packet_counter, iv_send = sc_send_packet(send, recv, CMD_SC_SERVER_ADDITIONAL_INFO, b"SERVER::will_shutdown_in_2h", kenc_send, kmac_send, send_packet_counter, iv_send)

    # Now ask for our secret in secure channel mode
    send_packet_counter, iv_send = sc_send_packet(send, recv, CMD_GET_FLAG, b"PLEASE_GIVE_ME_YOUR_SECRET_AS_I_ASK_KINDLY_DEAR_CLIENT!".center(205, b"_"), kenc_send, kmac_send, send_packet_counter, iv_send)
    cmd, payload, recv_packet_counter, iv_recv = sc_recv_packet(send, recv, kenc_recv, kmac_recv, recv_packet_counter, iv_recv)
    if cmd != CMD_GET_FLAG:
        # This is an unexpected response
        logger.error("[SERVER] Error: unexpected response at this stage. Aborting.")
        thread_exit()

    logger.info("[SERVER] Finished our job ... bye!")
