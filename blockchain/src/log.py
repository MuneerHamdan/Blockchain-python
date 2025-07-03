import socket
import sys
import base64
import hashlib
import re

def fixstring(message):
    message = message.replace('\\t', ' ')
    message = message.replace('\t', ' ')
    message = message.replace('\\n', ' ')
    message = message.replace('\n', ' ')
    message = message.strip()
    return ''.join(re.findall(r'[A-za-z0-9\s\(\)]+', message))
    

def genproofofwork(message, difficulty=20): # CHANGE LATER HAS TO BE 20
    proof = ""
    target = "0" * (difficulty // 4)

    counter = 0
    while True:
        proofthing = f"{proof}:{message}"
        proofhash = hashlib.sha256(proofthing.encode('utf-8')).digest()
        base64hash = base64.b64encode(proofhash).decode('utf-8')

        if base64hash[:difficulty // 4] == target:
            return proof

        proof = incrementstring(proof)
        counter += 1

        if counter % 1000 == 0:
            print(f"trying proof of work {proof}, counter {counter}...")


def incrementstring(s):
    if not s:
        return 'a'

    slist = list(s)
    i = len(slist) - 1

    while i >= 0:

        if slist[i] == 'z':
            slist[i] = 'a'
            i -= 1
        else:
            slist[i] = chr(ord(slist[i]) + 1)
            break
    else:
        slist.insert(0,'a')

    return ''.join(slist)


def send_string_to_server(port, message):
    try:
        # Connect to the server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', port))


        ######################
        ### Convert any whitespace to spaces
        ### Modify the messsage to include the proof-of-work (Pow+':'+message)
        ######################

        fixedmessage = fixstring(message)
        
        proof = genproofofwork(fixedmessage)

        final = proof + ":" + fixedmessage
        print(final)


        with client_socket.makefile('r') as server_in, client_socket.makefile('w') as server_out:
            # Send the message to the server, terminated by a newline
            server_out.write(final + "\n")
            server_out.flush()

            # Receive and print the confirmation message from the server
            response = server_in.readline().strip()
            print(f"Server response: {response}")

    except Exception as e:
        print(f"Error communicating with server: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: log <port> <message>")
    else:
        port = int(sys.argv[1])
        message = sys.argv[2]
        send_string_to_server(port, message)

