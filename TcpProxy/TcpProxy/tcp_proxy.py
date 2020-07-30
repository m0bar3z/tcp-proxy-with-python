import sys
import socket
import threading


def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, str) else 2
    for i in range(0, len(src), length):
        s = src[i:i+length]
        hexa = " ".join(map("{0:0>2X}".format,src))
        text = "".join([chr(x) if 0x20 <= x < 0x7F else "." for x in s])
        result.append("%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
    
    print("\n".join(result))


# modify any responses destined for the local host
def response_handler(buffer):
    # perform packet modifications
    return buffer


# modify any requests destined for the remote host
def request_handler(buffer):
    # perform packet modifications
    return buffer


def receive_from(connection):
    buffer = ""
    connection.settimeout(3)

    try:
        while True:
            data = connection.recv(4096)
            buffer += data.decode()
            if not data:
                break
    except:
        pass

    return buffer.encode()


def proxy_handler(client_socket, remote_host, remote_port, receive_first):

    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    remote_socket.connect((remote_host, remote_port))
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

        remote_buffer = response_handler(remote_buffer)

        if len(remote_buffer):
            print("[<==] Sending", len(remote_buffer), "bytes to localhost.")
            client_socket.send(remote_buffer)
            

    while True:
        local_buffer = receive_from(client_socket)
        #local_buffer = client_socket.recv(4096)
        #print("test test test")
        #print("len", len(local_buffer))
        if len(local_buffer):
            print("[==>] Received", len(local_buffer), "bytes from localhost.")
            hexdump(local_buffer)

            request_handler(local_buffer)

            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

        remote_buffer = receive_from(remote_socket)

        if len(remote_buffer):
            print ("[<==] Received", len(remote_buffer), "bytes from remote.")
            hexdump(remote_buffer)
            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            
            print ("[<==] Sent to localhost.")
            # if no more data on either side, close the connections
            if not len(local_buffer) or not len(remote_buffer):
                client_socket.close()
                remote_socket.close()
                print ("[*] No more data. Closing connections.")
                
                break


def server_loop(local_host, local_port, remote_host, remote_port, receive_first):

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except:
        print ("[!!] Failed to listen on", local_host, local_port)
        print ("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)

    print ("[*] Listening on", local_host, local_port)

    server.listen(5)

    while True:
        client_socket, addr = server.accept()
        print("[==>] recieved incoming connection from", addr[0] ,":", addr[1])

        proxy_thread = threading.Thread(target= proxy_handler, args=(client_socket, remote_host, remote_port, receive_first))
        proxy_thread.start()


def main():
    # no fancy command-line parsing here
    if len(sys.argv[:1]) != 5:
        print("Usage: tcp_proxy.py [localhost] [localport] [remotehost] [remoteport] [receivefirst]")
        print("Example: tcp_proxy.py 127.0.0.1 9000 0.0.0.0 10.12.132.1 9000 True")

        local_host = sys.argv[1]
        local_port = int(sys.argv[2])

        remote_host = sys.argv[3]
        remote_port = int(sys.argv[4])

        receive_first = sys.argv[5]

        if "True" in receive_first or "true" in receive_first or not receive_first:
            receive_first = True
        else:
            receive_first = False
            
        print("1", local_host, "2", local_port, "3", remote_host, "4", remote_port)
        server_loop(local_host, local_port, remote_host, remote_port, receive_first)


main()

