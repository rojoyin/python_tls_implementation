import logging
import socket
from typing import Any

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('tcp_server')


class TCPServer:
    def __init__(self, host: str = '127.0.0.1', port: int = 8443):
        self.host: str = host
        self.port: int = port
        self.socket : socket.socket | None = None
        self.connections: list[socket.socket] = []

    def start(self) -> None:
        # Create socket, bind, and start listening
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
        except Exception as e:
            logger.error(f"Failed to create socket: {e}")

    def accept_connection(self) -> tuple[socket, Any] | None:
        # Accept new client connections
        try:
            client_socket, client_address = self.socket.accept()
            self.connections.append(client_socket)
            return client_socket, client_address
        except Exception as e:
            logger.error(f"Failed to accept connection: {e}")


    def receive_data(self, client_socket) -> Any | None:
        # Receive data from a client
        try:
            return client_socket.recv(1024)
        except Exception as e:
            logger.error(f"Failed to receive data: {e}")
            self.remove_connection(client_socket)

    def send_data(self, client_socket, data) -> bool:
        # Send data to a client
        try:
            client_socket.send(data)
            return True
        except Exception as e:
            logger.error(f"Failed to send data: {e}")
            return False

    def close(self) -> None:
        for conn in self.connections:
            try:
                conn.close()
            except Exception as e:
                logger.error(f"Failed to close connection: {e}")

        if self.socket:
            self.socket.close()

        self.connections.clear()

    def remove_connection(self, client_socket):
        if client_socket in self.connections:
            self.connections.remove(client_socket)

    def run(self):
        """Run the server in a loop accepting connections."""
        self.start()
        logger.info(f"Server started on {self.host}:{self.port}")

        try:
            while True:
                conn_info = self.accept_connection()
                if conn_info:
                    client_socket, client_addr = conn_info
                    logger.info(f"Connection from {client_addr[0]}:{client_addr[1]}")
                    data = self.receive_data(client_socket)

                    if data:
                        self.send_data(client_socket, data)
                    else:
                        self.remove_connection(client_socket)

        except KeyboardInterrupt:
            logger.info("Server shutting down...")
        finally:
            self.close()

if __name__ == "__main__":
    server = TCPServer()
    server.run()
