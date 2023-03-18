import socket


def connect_client():
    # setting up a TCP socket to listen for incoming client requests
    server_address = ("127.0.0.200", 80)
    # A new socket is created using socket.socket() function
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # The socket is bound to the server address
    server_socket.bind(server_address)
    # The server socket starts listening for incoming connections
    server_socket.listen(1)
    while True:
        connection_socket, addr_client = server_socket.accept()
        request = connection_socket.recv(8196)
        print("[+] Get from client ", addr_client, ":", request)
        response = connect_redirect_server(request)
        connection_socket.sendall(response)
        connection_socket.close()
        break


def connect_redirect_server(request):
    server_address = ('127.0.0.255', 30290)
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind(("127.0.0.200", 20235))
    proxy_socket.connect(server_address)
    proxy_socket.sendall(request)
    response = b""
    while True:
        # read 1024 bytes from the socket (receive)
        bytes_read = proxy_socket.recv(1024)
        if not bytes_read:
            # nothing is received
            # file transmitting is done
            break
        response += bytes_read
        # write to the file the bytes we just received
    proxy_socket.close()
    return response


if __name__ == '__main__':
    connect_client()