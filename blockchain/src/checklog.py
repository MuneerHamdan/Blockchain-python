import os, sys
import base64
import hashlib


args = sys.argv
if len(args) > 1:
    print("run without arguments")
    sys.exit(1)

try:
    log = open("log.txt", "r")
except FileNotFoundError:
    print("failed: log.txt doesn't exist")

    try:
        loghead = open("loghead.txt", "r")
    except FileNotFoundError:
        print("failed: loghead.txt doesn't exist... exiting")
        sys.exit(1)

    print("exiting")
    sys.exit(1)

try:
    loghead = open("loghead.txt", "r")
except FileNotFoundError:
    print("failed: loghead.txt doesn't exist... exiting")
    log.close()
    sys.exit(1)


# H = last24(b64encode(sha256(line)))
logstr = log.readline().strip("\n")
linecount = 1
hashstr = hashlib.sha256(logstr.encode("utf-8")).digest()
base64str = base64.b64encode(hashstr).decode("utf-8")
last24 = base64str[-24:]

if len(logstr) != 0:
    logstrstuff = logstr.split()
    if logstrstuff[3] != "start":
        print("failed: hash value of first line does not equal (without quotes) \"start\"... exiting")
        sys.exit(1)
else: 
    if os.path.getsize("log.txt") == 0:
        print("failed: log.txt empty... exiting")
        sys.exit(1)
    else:
        print("failed: missing starting line... exiting")
        sys.exit(1) 


while True:
    logstr = log.readline().strip("\n")

    if len(logstr) == 0:
        break

    logstrstuff = logstr.split()
    if logstrstuff[3] != last24:
        print(f"failed: error at line {linecount}... exiting")
        log.close()
        loghead.close()
        sys.exit(1)

    linecount += 1
    hashstr = hashlib.sha256(logstr.encode("utf-8")).digest()
    base64str = base64.b64encode(hashstr).decode("utf-8")
    last24 = base64str[-24:]

hashheadpointer = loghead.readline().strip()

if hashheadpointer == last24:
    print("valid")
    log.close()
    loghead.close()
    sys.exit(0)
else: 
    print(f"failed: error at line number {linecount}... exiting")
    
    log.close()
    loghead.close()
    sys.exit(1)

log.close()
loghead.close()
