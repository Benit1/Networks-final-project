import socket


def connect_app():
    server_address = ('127.0.0.255', 30290)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(server_address)
    server_socket.listen(1)
    while True:
        connection_socket, addr_client = server_socket.accept()
        print("Get from client ", addr_client)
        handle_request(connection_socket)
        break
    server_socket.close()


def handle_request(connection_socket):
    data = connection_socket.recv(8196)
    # The received data is decoded into a string
    request = data.decode()
    # extracted from the request string
    path = request.split(' ')[1]

    # Extract the filename from the path
    file_name = path.split('/')[-1]
    print(file_name)
    if not file_name.endswith('.pdf'):
        response = b"HTTP/1.1 404 Not Found\r\n\r\n"
        connection_socket.sendall(response)
        connection_socket.close()
        return

    send_file(connection_socket, file_name)


def send_file(connection_socket, file_name):
    # The file with the given file name is opened in binary mode
    with open(file_name, 'rb') as file:
        content = file.read()
        # A response is created as a byte string containing the HTTP header and the file content
        response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/pdf\r\n"
                b"Content-Length: " + str(len(content)).encode() + b"\r\n"
                                                                   b"\r\n" + content
        )
        connection_socket.sendall(response)
        connection_socket.close()
        return


if __name__ == '__main__':
    connect_app()