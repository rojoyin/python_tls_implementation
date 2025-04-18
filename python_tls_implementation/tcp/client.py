import logging
import socket

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('tcp_client')


class TCPClient:
    def __init__(self):
        # Initialize client properties
        self.socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected: bool  = False

    def connect(self, host: str, port: int) -> bool:
        try:
            self.socket.connect((host, port))
            self.connected = True
            return True
        except Exception as e:
            logger.error(f"Failed to connect to {host}:{port}: {e}")
            return False

    def send_data(self, data: bytes) -> bool:
        # Send data to the server
        if not self.connected:
            logger.error("Not connected to any server")
            return False
        try:
            self.socket.send(data)
            return True
        except Exception as e:
            logger.error(f"Failed to send data: {e}")
            self.connected = False
            return False


    def receive_data(self, size: int = 1024) -> bytes:
        # Receive data from the server
        if not self.connected:
            logger.error("Not connected to any server")
            return b''
        try:
            data = self.socket.recv(size)

            if not data:
                logger.info("Connection closed by server")
                self.connected = False
            return data
        except Exception as e:
            logger.error(f"Failed to receive data: {e}")
            self.connected = False
            return b''

    def close(self) -> None:
        try:
            self.socket.close()
        except Exception as e:
            logger.error(f"Failed to close connection: {e}")
        finally:
            self.connected = False


if __name__ == "__main__":
    client = TCPClient()
    if client.connect("127.0.0.1", 8443):
        logger.info("Connected to server")

        # Send a test message
        message = b"Hello, server!"
        if client.send_data(message):
            logger.info(f"Sent: {message}")

            # Receive response
            response = client.receive_data()
            if response:
                logger.info(f"Received: {response}")

        client.close()
