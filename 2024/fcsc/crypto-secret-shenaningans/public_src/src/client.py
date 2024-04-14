#### Client implementation

from common import *

CLIENT_VERSION_STRING = b"CLIENT_V_1"
send_packet_counter = 0
recv_packet_counter = 0

# Load server public key
with open("data/server_public_key.der", "rb") as f:
    a = f.read()
    server_public_key_raw = a
    server_public_key = ECC.import_key(a)

# Secure channel state
secure_channel = False
INITIAL_SEND_IV = b'\xbb' * 16
INITIAL_RECV_IV = b'\xaa' * 16

def main_client(send, recv):
    global send_packet_counter
    global recv_packet_counter
    global secure_channel

    logger.warning("[CLIENT] Spawning the client...")

    ##### Exchange our version in clear
    send_packet_counter = clear_send_packet(send, recv, CMD_STRING_VERSION, CLIENT_VERSION_STRING, send_packet_counter)
    cmd, server_version, recv_packet_counter = clear_recv_packet(send, recv, recv_packet_counter, expected_cmd=CMD_STRING_VERSION)
    logger.warning(f"[CLIENT] Received server version {server_version}")

    ##### Proceed with key exchange
    # Generate an ephemeral ECDH private key and the corresponding serialized point
    x = ECDH_gen_ephemeral_private_key()
    Gx = ECDH_gen_public_data(x)

    # Send the CMD_KEXDH_INIT to initialize the key exchange
    send_packet_counter = clear_send_packet(send, recv, CMD_KEXDH_INIT, Gx, send_packet_counter)

    # Wait for a response from the server
    while True:
        cmd, payload, recv_packet_counter = clear_recv_packet(send, recv, recv_packet_counter)
        if cmd == CMD_IGNORE:
            logger.warning("[CLIENT] CMD_IGNORE received")
            # In case of ignore command, well, ignore and loop...
            continue
        elif cmd == CMD_PING:
            logger.warning("[CLIENT] CMD_PING received")
            # In case of "ping", respond with "pong" with the received payload and loop
            send_packet_counter = clear_send_packet(send, recv, CMD_PONG, payload, send_packet_counter)
            continue
        elif cmd == CMD_KEXDH_REPLY:
            logger.warning("[CLIENT] CMD_KEXDH_REPLY received")
            # In case of key exchange init, this is it we have the data we have been waiting to continue
            # the key exchange
            break 
        else:
            # This is an unexpected command at this stage
            logger.error("[CLIENT] Error in possible commands during key exchange. Aborting.")
            thread_exit()

    # Split the payload in its components: ephemeral ECDH public key and ECDSA signature of the key exchange
    if len(payload) < 64:
        logger.error("[CLIENT] Error in CMD_KEXDH_REPLY payload length. Aborting.")
        thread_exit()

    Gy, sig = payload[:-64], payload[-64:]

    # Here, we compute the shared secret from CMD_KEXDH_REPLY
    shared_secret = ECDH_gen_shared_secret(x, Gy)

    # Check that the key exchange is indeed OK and that this is the server we are supposed to talk to
    check = verify_key_exchange(server_version + CLIENT_VERSION_STRING + Gx + Gy + server_public_key_raw + shared_secret, server_public_key, sig)
    if not check:
        logger.error("[CLIENT] Error: key exchange signature is not verified. Aborting.")
        thread_exit()

    # ACK the secure channel establishement by sending CMD_NEWKEYS
    send_packet_counter = clear_send_packet(send, recv, CMD_NEWKEYS, b"", send_packet_counter)

    # The only possible commands here are IGNORE or CMD_NEWKEYS (to ACK our secure channel) in clear.
    # Everything else is an error.
    while True:
        cmd, payload, recv_packet_counter = clear_recv_packet(send, recv, recv_packet_counter)
        if cmd == CMD_IGNORE:
            logger.warning("[CLIENT] CMD_IGNORE received")
            # In case of ignore command, well ignore and loop ...
            continue
        elif cmd == CMD_NEWKEYS:
            logger.warning("[CLIENT] CMD_NEWKEYS received")
            # OK, we got to secure channel
            break
        else:
            # This is an unexpected command at this stage
            logger.error("[CLIENT] Error in possible commands during key exchange. Aborting.")
            thread_exit()

    # Derive the secure channel keys
    kenc_recv, kmac_recv = derive_secure_channel_keys(b"SERVERTOCLIENT", shared_secret)
    kenc_send, kmac_send = derive_secure_channel_keys(b"CLIENTTOSERVER", shared_secret)

    # Set secure channel as active
    logger.warning("[CLIENT] Secure channel is ON!")
    secure_channel = True
    iv_recv = INITIAL_RECV_IV
    iv_send = INITIAL_SEND_IV

    # Wait for encrypted commands in secure channel mode, or non-encrypted in non secure channel mode
    while True:
        if secure_channel:
            cmd, payload, recv_packet_counter, iv_recv = sc_recv_packet(send, recv, kenc_recv, kmac_recv, recv_packet_counter, iv_recv)
        else:
            cmd, payload, recv_packet_counter = clear_recv_packet(send, recv, recv_packet_counter)

        logger.debug(f'[DEBUG] cmd = {cmd[0]:0>2x}')
        if cmd == CMD_DISABLE_SC:
            logger.debug('[DEBUG] DING DING DING !!!')

        # Switch on command received
        if cmd == CMD_IGNORE:
            # This is an ignore command, well, ignore it!
            logger.warning("[CLIENT] CMD_IGNORE received")
            continue
        elif cmd == CMD_PING:
            logger.warning("[CLIENT] CMD_PING received")
            resp_cmd = CMD_PONG
            payload_to_send = payload
        elif cmd == CMD_STRING_VERSION:
            logger.warning("[CLIENT] CMD_STRING_VERSION received")
            resp_cmd = cmd
            payload_to_send = CLIENT_VERSION_STRING
        elif cmd == CMD_DISABLE_SC:
            # This can only be excuted when the secure channel is set
            logger.warning("[CLIENT] CMD_DISABLE_SC received")
            if not secure_channel:
                logger.error("[CLIENT] Error: CMD_DISABLE_SC while secure is not active. Aborting.")
                thread_exit()
            # Disable the secure channel
            secure_channel = False
            continue
        elif cmd == CMD_GET_FLAG:
            logger.warning("[CLIENT] CMD_GET_FLAG received")
            with open("data/flag.txt", "rb") as f:
                flag = f.read()
            resp_cmd = cmd
            payload_to_send = flag
        elif cmd == CMD_SC_SERVER_ADDITIONAL_INFO:
            # Receive in the secure channel the sensitive data of the server
            logger.warning("[CLIENT] CMD_SC_SERVER_ADDITIONAL_INFO received")
            if not secure_channel:
                logger.error("[CLIENT] Error: CMD_SC_SERVER_ADDITIONAL_INFO while secure is not active. Aborting.")
                thread_exit()
            continue            
        else:
            # This is an unexpected command at this stage
            logger.error("[CLIENT] Error: unexpected command at this stage. Aborting.")
            thread_exit()

        if secure_channel:
            send_packet_counter, iv_send = sc_send_packet(send, recv, resp_cmd, payload_to_send, kenc_send, kmac_send, send_packet_counter, iv_send)
        else:
            send_packet_counter = clear_send_packet(send, recv, resp_cmd, payload_to_send, send_packet_counter)

        # If we have successfully serviced ou FLAG, we are done!
        if cmd == CMD_GET_FLAG:
            break
    logger.warning("[CLIENT] Finished our job... bye!")
