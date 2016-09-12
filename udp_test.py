import socket
import sys


def main():
    server = sys.argv[1]
    port   = int(sys.argv[2])
    data   = sys.argv[3]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 12345))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.sendto(data.encode("utf-8"), (server, port))
    # s.close()
    data, addr = s.recvfrom(8192)
    s.close()
    print("[ADDR] -- ", addr)
    print("[DATA] -- ", data)

if __name__ == '__main__':
    main()