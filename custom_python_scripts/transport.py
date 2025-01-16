import socket

import threading
import time


def connect_tcp(remote_host: str, remote_port: int, local_host: str | None = None, local_port: int = None, happy_eyeballs_delay: float = 0.25):
    """
    Implementation of Happy Eyeballs/Fast Fallback algorithm.
    Tries IPv6 and IPv4 addresses sequentially with a delay.
    """
    # Resolve remote host
    addr_info = socket.getaddrinfo(remote_host, remote_port, socket.AF_UNSPEC, socket.SOCK_STREAM)

    # Separate IPv6 and IPv4 addresses & select the first of each
    ipv6_address = next((info for info in addr_info if info[0] == socket.AF_INET6), None)
    ipv4_address = next((info for info in addr_info if info[0] == socket.AF_INET), None)

    if not ipv6_address and not ipv4_address:
        raise RuntimeError('No address could be resolved for the remote host')

    # Shared result and lock
    result = {'socket': None, 'error': None}
    result_lock = threading.Lock()

    def attempt_connection(address_info):
        """Attempt to connect to the given address."""
        nonlocal result
        try:
            family, socktype, proto, _, sockaddr = address_info
            with socket.socket(family, socktype, proto) as sock:
                if local_host:
                    sock.bind((local_host, local_port))
                sock.connect(sockaddr)
                with result_lock:
                    if result['socket'] is None:
                        result['socket'] = sock.detach()  # Detach so the context manager doesn't close it
        except Exception as e:
            with result_lock:
                if result['socket'] is None and result['error'] is None:
                    result['error'] = e

    # Start threads
    threads = []
    if ipv6_address:
        threads.append(threading.Thread(target=attempt_connection, args=(ipv6_address,)))
        threads[-1].start()

    if ipv4_address:
        if ipv6_address:
            time.sleep(happy_eyeballs_delay)
        threads.append(threading.Thread(target=attempt_connection, args=(ipv4_address,)))
        threads[-1].start()

    # Wait for threads to complete
    for thread in threads:
        thread.join()

    # Return the first successful connection or raise an error
    if result['socket']:
        return socket.fromfd(result['socket'], socket.AF_INET, socket.SOCK_STREAM)
    if result['error']:
        raise result['error']
    raise RuntimeError('Failed to connect to any address')


class TCPTransportClient:
    '''
    A simple wrapper for sending and receiving data over a TCP connection using python sockets.
    '''
    def __init__(self, socket: socket.socket | None = None):
        self.socket = socket

    def connect(self, remote_host: str, remote_port: int, local_host: str | None = None, happy_eyeballs_delay: float = 0.25):
        """
        Use addresses not names.
        """
        if self.socket is not None:
            print('Cannot Connect, already connected.')
            return self.socket
        try:
            self.socket = connect_tcp(remote_host, remote_port, local_host, happy_eyeballs_delay)
        except Exception as e:
            print(f'Failed to connect: {e}')
            self.socket = None

    def close(self):
        if self.socket is None:
            print('Cannot Close, not connected.')
            return
        try:
            self.socket.close()
        finally:
            self.socket = None

    def send(self, data: bytes):
        if self.socket is None:
            print('Cannot Send, not connected.')
            return
        try:
            self.socket.send(data)
        except Exception as e:
            print(f'Failed to send: {e}')
            self.close()

    def recv(self, buffer_size: int = 1024) -> bytes:
        if self.socket is None:
            print('Cannot Recv, not connected.')
            return
        try:
            return self.socket.recv(buffer_size)
        except Exception as e:
            print(f'Failed to recv: {e}')
            self.close()

    def sendrecv(self, data: bytes, buffer_size: int = 1024) -> bytes:
        self.send(data)
        return self.recv(buffer_size)


def main():
    # Test the TCPTransportClient
    client = TCPTransportClient()
    client.connect('www.google.com', 80)
    client.send(b'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n')
    response = client.recv()
    print(response.decode())
    client.close()


if __name__ == '__main__':
    main()
