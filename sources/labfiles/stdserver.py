#!/usr/bin/env python3
import socket
from dlpModule import DLPSolver

DLP_BRUTEFORCE = "BF"
DLP_SPH = "SPH"


def start_routine(solver:DLPSolver) -> None:
    print('Choose Method (BruteForce/SilverPohligHellman) [BF/SPH]> ', end="")
    try:
        method = input()
        if method != DLP_BRUTEFORCE and method != DLP_SPH:
            print('Method Invalid')
            print(method)
            return


        a,b,p = None, None, None

        print('a = ', end="")
        a = int(input())
        print('b = ', end="")
        b = int(input())
        print('p = ', end="")
        p = int(input())
    except Exception as e:
        print(e)
        return


    if method == DLP_BRUTEFORCE:
        result = solver.dlp_bruteforce(a, b, p)
        print(f'result = {result}')
    elif method == DLP_SPH:
        result = solver.dlp_sph(a, b, p)
        print(f'result = {result}')
    
    return



def main() -> None:
    solver = DLPSolver()
    start_routine(solver)



if __name__ == "__main__":
    main()