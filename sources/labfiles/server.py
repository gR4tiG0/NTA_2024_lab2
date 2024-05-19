#!/usr/bin/env python3
import socket
from dlpModule import DLPSolver

DLP_BRUTEFORCE = "BF"
DLP_SPH = "SPH"


def start_routine(cs:socket, solver:DLPSolver) -> None:
    cs.sendall(b'Choose Method (BruteForce/SilverPohligHellman) [BF/SPH]> ')
    try:
        method = cs.recv(4).strip().decode()
        if method != DLP_BRUTEFORCE and method != DLP_SPH:
            print('Method Invalid')
            print(method)
            return


        a,b,p = None, None, None

        cs.sendall(b'a = ')
        a = int(cs.recv(1024))
        cs.sendall(b'b = ')
        b = int(cs.recv(1024))
        cs.sendall(b'p = ')
        p = int(cs.recv(1024))
    except Exception as e:
        print(e)
        return


    if method == DLP_BRUTEFORCE:
        result = solver.dlp_bruteforce(a, b, p)
        cs.sendall(b'result = ' + str(result).encode())
    elif method == DLP_SPH:
        result = solver.dlp_sph(a, b, p)
        cs.sendall(b'result = ' + str(result).encode())
    
    return



def main() -> None:
    solver = DLPSolver()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = ('localhost', 1337)
    server_socket.bind(server_address)
    server_socket.listen(1)

    while True:        
        client_socket, client_address = server_socket.accept()
        try:
            start_routine(client_socket, solver)
        finally:
            client_socket.close()



if __name__ == "__main__":
    main()