# client code with ssl things
import socket
import ssl

BUFFER_SIZE = 1024  # Define BUFFER_SIZE here

def authenticate(ssl_client_socket):
    # Authenticate with the server
    while True:
        username = input("Enter username: ")
        password = input("Enter password: ")
        ssl_client_socket.sendall(username.encode())
        ssl_client_socket.sendall(password.encode())

        # Receive authentication response
        response = ssl_client_socket.recv(BUFFER_SIZE).decode()
        print(response)

        if "Authentication successful" in response:
            return True
        else:
            print("Authentication failed. Please try again.")

def main():
    # Get server's IP address and port number from user
    SERVER_HOST = input("Enter server's IP address: ")
    SERVER_PORT = int(input("Enter server's port number: "))

    # Create a socket and wrap it with SSL
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_client_socket = ssl.wrap_socket(client_socket, ssl_version=ssl.PROTOCOL_TLSv1_2, cert_reqs=ssl.CERT_NONE)

    try:
        # Connect to the server
        server_address = (SERVER_HOST, SERVER_PORT)
        ssl_client_socket.connect(server_address)
        print(f"Connected to server {SERVER_HOST} on port {SERVER_PORT} using SSL/TLS")

        # Attempt to authenticate with the server
        authenticated = authenticate(ssl_client_socket)
        while not authenticated:
            authenticated = authenticate(ssl_client_socket)

        # Now that authentication is successful, handle command execution
        while True:
            # Get command from the user
            message = input("Enter a command (or 'quit' to exit): ")

            # Send command to the server
            ssl_client_socket.sendall(message.encode())

            if message.lower() == "quit":
                break

            # Receive data from the server
            data = ssl_client_socket.recv(BUFFER_SIZE).decode()
            print(f"Received data from server: {data}")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        # Close the SSL/TLS socket
        ssl_client_socket.close()

if __name__ == "__main__":
    main()
