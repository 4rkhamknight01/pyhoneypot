import socket
import atexit

# Local IP/Port for the honeypot to listen on (SSH and HTTP)
LHOST = '0.0.0.0'
LSSH = 22
LHTTP = 80
LFTP = 21

# Remote IP/Port to send the log data to (TCP)
RHOST = '10.12.35.62'
RPORT = 9000

# Banner displayed when connecting to the honeypot
BANNER = '220 test honeypot \nName: '

# Socket timeout in seconds
TIMEOUT = int(10)

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def http():
    print('[*] Honeypot starting on ' + LHOST + ':' + str(LHTTP))
    atexit.register(exit_handler)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((LHOST, LHTTP))
    listener.listen(5)
    while True:
        (insock, address) = listener.accept()
        insock.settimeout(TIMEOUT)
        print('[*] Connection from : ' + address[0] + ':' + str(address[1]) + ' on port ' + str(LHTTP))
        try:
            insock.send(BANNER)
            data = insock.recv(1024)
        except socket.error as e:
            sendlogHTTP(address[0], 'Error ' + str(e))
        else:
            sendlogHTTP(address[0], data)
        finally:
            insock.close()

def ssh():
    print('[*] Honeypot starting on ' + LHOST + ':' + str(LSSH))
    atexit.register(exit_handler)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((LHOST, LSSH))
    listener.listen(5)
    while True:
        (insock, address) = listener.accept()
        insock.settimeout(TIMEOUT)
        print('[*] Connection from : ' + address[0] + ':' + str(address[1]) + ' on port ' + str(LSSH))
        try:
            insock.send(BANNER)
            data = insock.recv(1024)
        except socket.error as e:
            sendlogSSH(address[0], 'Error ' + str(e))
        else:
            sendlogSSH(address[0], data)
        finally:
            insock.close()

def ftp():
    print('[*] Honeypot starting on ' + LHOST + ':' + str(LFTP))
    atexit.register(exit_handler)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((LHOST, LFTP))
    listener.listen(5)
    while True:
        (insock, address) = listener.accept()
        insock.settimeout(TIMEOUT)
        print('[*] Connection from : ' + address[0] + ':' + str(address[1]) + ' on port ' + str(LFTP))
        try:
            insock.send(BANNER)
            data = insock.recv(1024)
        except socket.error as e:
            sendlogFTP(address[0], 'Error ' + str(e))
        else:
            sendlogFTP(address[0], data)
        finally:
            insock.close()
        
def sendlogHTTP(fromip, message):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((RHOST, RPORT))
    s.send('IP:' + fromip + ' Port:' + str(LHTTP) + ' | ' + message.replace('\r\n', ' '))
    s.close()

def sendlogSSH(fromip, message):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((RHOST, RPORT))
    s.send('IP:' + fromip + ' Port:' + str(LSSH) + ' | ' + message.replace('\r\n', ' '))
    s.close()

def sendlogFTP(fromip, message):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((RHOST, RPORT))
    s.send('IP:' + fromip + ' Port:' + str(LFTP) + ' | ' + message.replace('\r\n', ' '))
    s.close()

def exit_handler():
    print("\n honeypot is shutting down")
    listener.close()


def main():
    type_input = str(input("enter From HTTP, SSH and FTP ports: "))
    if type_input == "HTTP":
        http()
    elif type_input == "SSH":
        ssh()
    else:
        ftp()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    
