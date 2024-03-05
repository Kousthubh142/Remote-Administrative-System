import socket
import ssl
import subprocess
import psutil
import time
import threading

SERVER_HOST = '0.0.0.0'  
SERVER_PORT = 5555
BUFFER_SIZE = 1024
QUIT_MESSAGE = "quit"

USER_DB = {
    '123': {'password': '123', 'loggedin': False},
    '456': {'password': '456', 'loggedin': False},
    '789': {'password': '789', 'loggedin': False},
    'pes': {'password': 'pesu', 'loggedin': False},
}

def authenticate_user(username, password):
    """Authenticate user based on provided username and password""" 
    user_data = USER_DB.get(username)
    if user_data and not user_data['loggedin'] and user_data['password'] == password:
        user_data['loggedin'] = True
        return True 
    return False

def handle_client(ssl_client_socket):
    """Handle incoming client connection"""
    authenticated = False
    username = ""

    # Authenticate user
    try:
        username = ssl_client_socket.recv(BUFFER_SIZE).decode().strip()
        password = ssl_client_socket.recv(BUFFER_SIZE).decode().strip()

        authenticated = authenticate_user(username, password)
        if not authenticated:
            ssl_client_socket.send(b"Authentication failed. Please try again.\n")
            return
        else:
            ssl_client_socket.send(b"Authentication successful. You are now logged in.\n")
    except Exception as e:
        ssl_client_socket.send(f"Error during authentication: {str(e)}\n".encode())
        return

    while True:
        try:
            command = ssl_client_socket.recv(BUFFER_SIZE).decode().strip()

            if command.lower() == QUIT_MESSAGE:
                USER_DB[username]['loggedin'] = False
                break

            if command.lower() == "cpu":
                cpu_usage = psutil.cpu_percent(interval=1)
                output = f"CPU Usage: {cpu_usage}%"
            elif command.lower() == "runtime":
                runtime = time.time() - start_time
                output = f"Server Runtime: {runtime} seconds"
            elif command.lower() == "network":
                network_stats = psutil.net_io_counters()
                bytes_sent_mb = round(network_stats.bytes_sent / (1024 ** 2), 2)
                bytes_recv_mb = round(network_stats.bytes_recv / (1024 ** 2), 2)
                output = f"Network Performance:\nBytes Sent: {bytes_sent_mb} MB\nBytes Received: {bytes_recv_mb} MB"
            elif command.lower() == "memory":
                memory_stats = psutil.virtual_memory()
                total_gb = round(memory_stats.total / (1024 ** 3), 2)
                available_gb = round(memory_stats.available / (1024 ** 3), 2)
                used_gb = round(memory_stats.used / (1024 ** 3), 2)
                output = f"Memory Usage:\nTotal: {total_gb} GB\nAvailable: {available_gb} GB\nUsed: {used_gb} GB"
            else:
                output = subprocess.getoutput(command)

            ssl_client_socket.send(output.encode())
        except Exception as e:
            error_message = f"Error executing command: {str(e)}"
            ssl_client_socket.send(error_message.encode())

    ssl_client_socket.close()
    USER_DB[username]['loggedin'] = False

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"[*] Listening on {SERVER_HOST}:{SERVER_PORT}")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"[*] Accepted connection from {client_address[0]}:{client_address[1]}")

            ssl_client_socket = context.wrap_socket(client_socket, server_side=True)

            client_handler = threading.Thread(target=handle_client, args=(ssl_client_socket,))
            client_handler.start()
    except KeyboardInterrupt:
        print("[*] Shutting down")
        server_socket.close()

if __name__ == "__main__":
    start_time = time.time()
    main()



