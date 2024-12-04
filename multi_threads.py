import socket
import threading
import time
import os
# Function to handle socket connection


def connect():
    # Define server address and port (change these as needed)
    server_ip = '127.0.0.1'  # Localhost for example
    server_port = 12345       # Example port
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the server
        s.connect((server_ip, server_port))

        print(
            f"Connected to {server_ip}:{server_port} in thread {threading.current_thread().name}")
        # Close the socket connection
        s.close()

    except Exception as e:
        print(f"Failed to connect: {e}")
        while True:
            x = 0


# Function to handle key press (blocking)


def wait_for_keypress():
    while True:
        input("Press Enter to initiate a socket connection (or type 'exit' to quit)")

        # Start a new thread to handle the socket connection
        thread = threading.Thread(target=connect)
        thread.start()

# Main function


def main():
    print(os.getpid())
    print("Socket connection script running. Press Enter to initiate a connection.")
    wait_for_keypress()


if __name__ == "__main__":
    main()
