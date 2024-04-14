# Implementation of the sniffer emulation

# Import server and client functions
from server import *
from client import *

import threading, os, time, inputimeout

# Our global variable holding the two communications channels as well as their locks:
#   - From server to client
#   - From client to server
server_to_client = b""
client_to_server = b""

server_to_client_lock = threading.Lock()
client_to_server_lock = threading.Lock()

MAX_BUF_SIZE = 2048

### Sniffer MitM main hook
transparent_mitm = False
user_action = "Possible actions are: (T) always transparent from now on (R) read the channel (E) edit the channel (Q) quit actions\n"
def other_lock_acquire(kind):
    global client_to_server_lock
    global server_to_client_lock
    if kind == "CLIENT_SEND":
        server_to_client_lock.acquire()
    elif kind == "SERVER_SEND":
        client_to_server_lock.acquire()
    else:
        return

def other_lock_release(kind):
    global client_to_server_lock
    global server_to_client_lock
    if kind == "CLIENT_SEND":
        server_to_client_lock.release()
    elif kind == "SERVER_SEND":
        client_to_server_lock.release()
    else:
        return

def patch_channel(kind, new_channel_state):
    global client_to_server
    global server_to_client
    if kind == '0':
        server_to_client = new_channel_state
    elif kind == '1': 
        client_to_server = new_channel_state
    else:
        return

def sniffer_mitm_action(kind):
    global transparent_mitm
    global client_to_server_lock
    global client_to_server
    global server_to_client_lock
    global server_to_client

    # Lock the other channel as we want to freeze everything as we are about
    # to observe or modify stuff in any channel
    other_lock_acquire(kind)
    if transparent_mitm:
        other_lock_release(kind)
        return
    else:
        print(f"-> Man-in-the-Middle hook action: {kind}")
        print(f"-> What do you want to do?")
        # Actions asked from the user
        while True:
            try:
                # Wait for user input with timeout 
                action = inputimeout.inputimeout(user_action, timeout = 10)
            except:
                print("-> Error in I/O, quitting ...")
                logger.error(f"[SNIFFER] Error in I/O, quitting ...")
                os._exit(-1)

            if len(action) == 0:
                continue

            # check that the action is valid
            if action[0] not in "TREQ":
                print(f"-> Error: unkown asked action {action}")
                logger.error(f"[SNIFFER] Error: unkown asked action {action}")
                continue

            if action[0] == 'T':
                logger.error(f"[SNIFFER] Command 'T' asked")
                if len(action) != 1:
                    print("-> Error in command 'T' format")
                    logger.error(f"[SNIFFER] Error in command 'T' format")
                    continue
                transparent_mitm = True
                continue

            elif action[0] == 'R':
                if len(action) != 2:
                    print("-> Error in command 'R' format (accepted: R0 or R1)")
                    logger.error(f"[SNIFFER] Error in command 'R' format (accepted: R0 or R1)")
                    continue
                # Print the hexadecimal content of the indexed channel: 0 for server to client, 1 for client to server
                if action[1] == '0':
                    logger.error(f"[SNIFFER] action 'R0' asked")
                    print(server_to_client.hex())
                elif action[1] == '1':
                    logger.error(f"[SNIFFER] action 'R1' asked")
                    print(client_to_server.hex())
                else:
                    print("-> Error: type of channel must be 0 (server to client) or 1 (client to server) ...")
                    logger.error(f"[SNIFFER] Error: type of channel must be 0 (server to client) or 1 (client to server) ...")
                continue

            elif action[0] == 'E':
                if len(action) < 2:
                    print("-> Error in command 'E' format (acccepted: E0 or E1)")
                    logger.error(f"[SNIFFER] Error in command 'E' format (accepted: E0 or E1)")
                    continue
                if action[1] != '0' and action[1] != '1':
                    print("-> Error: type of channel must be 0 (server to client) or 1 (client to server) ...")
                    logger.error(f"Error: type of channel must be 0 (server to client) or 1 (client to server) ...")
                    continue
                if action[1] == '0':
                    logger.error(f"[SNIFFER] action 'E0' asked")
                else:
                    logger.error(f"[SNIFFER] action 'E1' asked")

                # Parse the user hexadecimal input
                try:
                    new_channel_state = bytes.fromhex(action[2:])
                except:
                    print("-> Error getting hexadecimal input ...")
                    logger.error(f"[SNIFFER] Error getting hexadecimal input ...")
                    continue

                if len(new_channel_state) > MAX_BUF_SIZE:
                    print(f"-> Error: provided new channel length {len(new_channel_state)} is too big (> {MAX_BUF_SIZE})")
                    logger.error(f"[SNIFFER] Error: unkown asked action {action}")
                    continue

                patch_channel(action[1], new_channel_state)
                continue

            elif action[0] == 'Q':
                #logger.error(f"[SNIFFER] action 'Q' asked")
                if len(action) != 1:
                    print("-> Error in command 'Q' format")
                    logger.error(f"[SNIFFER] Error in command 'Q' format")
                    continue
                break

        other_lock_release(kind)
        return

def server_send(payload):
    global server_to_client_lock
    global server_to_client
    logger.info(f"[SERVER] Sending {len(payload)} len payload.")
    server_to_client_lock.acquire()
    # Sanity check
    if len(server_to_client) >= MAX_BUF_SIZE:
        logger.critical(f"Max size {MAX_BUF_SIZE} reached for server to client line. Aborting.")
        server_to_client_lock.release()
        thread_exit()
    server_to_client += payload
    # XXX Hook to sniffer
    sniffer_mitm_action("SERVER_SEND")
    server_to_client_lock.release()

def server_recv(sz):
    global client_to_server_lock
    global client_to_server
    # Wait until we have enough data
    while True:
        client_to_server_lock.acquire()
        l = len(client_to_server)
        client_to_server_lock.release()
        if l >= sz:
            break
    client_to_server_lock.acquire()
    payload = client_to_server[:sz]
    client_to_server = client_to_server[sz:]
    client_to_server_lock.release()
    logger.info(f"[SERVER] Received {len(payload)} len payload")
    return payload 
   

def client_send(payload):
    global client_to_server_lock
    global client_to_server
    logger.warning(f"[CLIENT] Sending {len(payload)} len payload.")
    client_to_server_lock.acquire()
    # Sanity check
    if len(client_to_server) >= MAX_BUF_SIZE:
        logger.critical(f"Max size {MAX_BUF_SIZE} reached for client to server line. Aborting.")
        client_to_server_lock.release()
        thread_exit()
    client_to_server += payload
    # XXX Hook to sniffer
    sniffer_mitm_action("CLIENT_SEND")
    client_to_server_lock.release()

def client_recv(sz):
    global server_to_client_lock
    global server_to_client
    # Wait until we have enough data
    while True:
        server_to_client_lock.acquire()
        l = len(server_to_client)
        server_to_client_lock.release()
        if l >= sz:
            break
    server_to_client_lock.acquire()
    payload = server_to_client[:sz]
    server_to_client = server_to_client[sz:]
    server_to_client_lock.release()
    logger.warning(f"[CLIENT] Received {len(payload)} len payload")
    return payload 

if __name__ == "__main__":

    ## Create two threads, one for the client and one for the server
    server_thread = threading.Thread(target = main_server, args = (server_send, server_recv))
    client_thread = threading.Thread(target = main_client, args = (client_send, client_recv))

    server_thread.start()
    client_thread.start()

    # In our "main" thread, we monitor the connection and exit after a timeout
    # to avoid "stalling" if there is no "action" on both channels
    last_server_to_client_sz = 0
    last_client_to_server_sz = 0
    count1 = 0
    count2 = 0

    # 100 ms sleep for the monitor
    MAIN_THREAD_MONITOR_SLEEP = 0.100

    # Max allowed stall counters
    MAX_CHANNEL_STALL_CTR = 100

    while True:
        server_to_client_lock.acquire()
        server_to_client_sz = len(server_to_client)
        server_to_client_lock.release()
        client_to_server_lock.acquire()
        client_to_server_sz = len(client_to_server)
        client_to_server_lock.release()
        if last_client_to_server_sz == client_to_server_sz:
            count1 += 1
        else:
            count1 = 0
            last_client_to_server_sz = client_to_server_sz
        if last_server_to_client_sz == server_to_client_sz:
            count2 += 1
        else:
            count2 = 0
            last_server_to_client_sz = server_to_client_sz
        time.sleep(MAIN_THREAD_MONITOR_SLEEP)
        if count1 >= MAX_CHANNEL_STALL_CTR and count2 >= MAX_CHANNEL_STALL_CTR:
            logger.info("[-] Communication seems stalled between server and client ... aborting!")
            os._exit(-1)

        # Check threads "liveness", exit if both client and server finished
        if not server_thread.is_alive() and not client_thread.is_alive():
            logger.info("[+] Server and client finished their job, bye!")
            break
