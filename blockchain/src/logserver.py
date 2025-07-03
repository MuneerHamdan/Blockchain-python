import socket
import sys, os
from datetime import datetime
import base64
import hashlib


def checkpow(proof, msg, difficulty=20): # CHANGE LATER HAS TO BE 20 
#    message = pow + ":" + msg
    proofthing = f"{proof}:{msg}"
    target = "0" * (difficulty // 4)
#    proofhash = hashlib.sha256(message.encode('utf-8')).digest()
#    base64hash = base64.b64encode(proofhash).decode('utf-8')
#    base64hash = base64hash + "\n"

    proofhash = hashlib.sha256(proofthing.encode('utf-8')).digest()
    base64hash = base64.b64encode(proofhash).decode('utf-8')
    return base64hash[:difficulty // 4] == target


def logmsg(message):
    try:
        log = open("log.txt")
        log.close()

        try: 
            if os.path.getsize("log.txt") != 0 and os.path.getsize("loghead.txt") != 0: # log.txt and loghead.txt empty -> add log based on head pointer
                loghead = open("loghead.txt", "r")
                hash_head_pointer = loghead.readline()
                hash_head_pointer = hash_head_pointer.strip()
                date_time = str(datetime.now())
                logentry = "".join(list(date_time)[:19]) + " - " + hash_head_pointer + " " + message.replace("\n", " ")
                loghead.close()
                
                loghead = open("loghead.txt", "w")
                hashstr = hashlib.sha256(logentry.encode("utf-8")).digest()
                base64str = base64.b64encode(hashstr).decode("utf-8")
                last24 = base64str[-24:]
                loghead.write(last24)
                loghead.close()

                log = open("log.txt", "a")
                log.write(logentry + "\n")
                log.close()

                print("successfully added new log to log.txt")
                
            elif os.path.getsize("log.txt") == 0 and os.path.getsize("loghead.txt") != 0: # only log.txt doesn't empty -> add log with "start", override loghead head pointer
                print("log.txt missing... creating new log file and overwriting loghead.txt with hash of new log")
                
                date_time = str(datetime.now())
                logentry = "".join(list(date_time)[:19]) + " - " + "start" + " " + message.replace('\n', ' ')

                loghead = open("loghead.txt", "w")
                hashstr = hashlib.sha256(logentry.encode("utf-8")).digest()
                base64str = base64.b64encode(hashstr).decode("utf-8")
                last24 = base64str[-24:]
                loghead.write(last24)
                loghead.close()

                log = open("log.txt", "a")
                log.write(logentry + "\n")
                log.close()

                print("successfully added new log to log.txt")

            elif os.path.getsize("loghead.txt") == 0 and os.path.getsize("log.txt") != 0: # only loghead empty -> error message empty file
                print("failed: loghead.txt missing... exiting")
                sys.exit(1)
            else: # both log and loghead are empty -> write new log according to head pointer
                print("log.txt and loghead.txt empty... creating initial log in log.txt and adding initial hashvalue to loghead.txt.")

                date_time = str(datetime.now())
                logentry = "".join(list(date_time)[:19]) + " - " + "begin" + " " + message.replace('\n', ' ')

                loghead = open("loghead.txt", "w")
                hashstr = hashlib.sha256(logentry.encode("utf-8")).digest()
                base64str = base64.b64encode(hashstr).decode("utf-8")
                last24 = base64str[-24:]
                loghead.write(last24)
                loghead.close()

                log = open("log.txt", "a")
                log.write(logentry + "\n")
                log.close()

                print("successfully added new log to log.txt")
                
        except FileNotFoundError: # only log.txt exist
            print("failed: log.txt missing... exiting")
            sys.exit(1)

    except FileNotFoundError:
        # only loghead.txt exists -> create log with "start" and override loghead head pointer
        print("log.txt doesn't exist -> creating log.txt and adding initial log to it")
        print("new hashvalue will overwrite old hashvalue or will add to it depending on whether it exists")

        if not os.path.exists("loghead.txt"):
            print("loghead.txt doesn't exist -> creating new loghead.txt and adding new hashvalue to it")
        else:
            print("loghead.txt exists -> new hashvalue will overwrite the old hashvalue")

        date_time = str(datetime.now())
        logentry = "".join(list(date_time)[:19]) + " - " + "start" + " " + message.replace('\n', ' ')

        loghead = open("loghead.txt", "w")
        hashstr = hashlib.sha256(logentry.encode("utf-8")).digest()
        base64str = base64.b64encode(hashstr).decode("utf-8")
        last24 = base64str[-24:]
        loghead.write(last24)
        loghead.close()

        log = open("log.txt", "w")
        log.write(logentry + "\n")
        log.close()

        print("successfully added new log to log.txt")


def handle_client(client_socket):
    try:
        # Use socket file interface to read line by line
        with client_socket.makefile('r') as client_in, client_socket.makefile('w') as client_out:
            # Receive the string from the client (terminated by a newline)
            message = client_in.readline().strip()
            print(f"Received: {message}")


            ########## YOUR CODE HERE ############
            ### Validate the the PoW in the message
            ### Strip the PoW from the message
            ### Read the last hash from loghead.txt
            ### Create the full line for the log entry
            ### Compute its hash
            ### Append the line to the log
            ### Update loghead.txt
            ### Add error checking
            #######################################

            try:
                proof, msg = message.split(":", 1)
            except ValueError:
                client_out.write("invalid message format\n")
                client_out.flush()
                return

            if not checkpow(proof, msg):
                client_out.write('invalid proof of work\n')
                client_out.flush()
                return


            message = message.split(':')[1]

            logmsg(message)


            client_out.write("log entry added\n")
            client_out.flush()

    except Exception as e:
        print(f"logserver: {e}")
    finally:
        client_socket.close()


def start_server():
    # Create a socket and bind it to any available port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 0))  # Bind to any available port
    server_socket.listen(5)

    # Get the port number and print it
    port = server_socket.getsockname()[1]
    print(f"Server listening on port {port}")

    # Continuously accept and handle clients
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        handle_client(client_socket)

if __name__ == "__main__":
    start_server()
