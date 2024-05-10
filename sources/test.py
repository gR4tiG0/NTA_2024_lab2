#!/usr/bin/env python3
from ctypes import CDLL, c_uint64, POINTER
import logging
from factorization.factorization import factor
from sage.all import factor as sage_factor
import time
logging.basicConfig(level=logging.DEBUG)


LIB_NAME = "./libdlp.so"

def initLib() -> CDLL:
    logging.debug(f"Initializing lib {LIB_NAME}")
    lib = CDLL(LIB_NAME)
    lib.dlp_bruteforce.argtypes = [c_uint64, c_uint64, c_uint64]
    lib.dlp_bruteforce.restype = c_uint64

    lib.dlp_spg.argtypes = [c_uint64, c_uint64, c_uint64]
    lib.dlp_spg.restype = c_uint64

    lib.power.argtypes = [c_uint64, c_uint64, c_uint64]
    lib.power.restype = c_uint64

    lib.inv.argtypes = [c_uint64, c_uint64]
    lib.inv.restype = c_uint64

    lib.factor.argtypes = [c_uint64]
    lib.factor.restype = c_uint64

    lib.isPrime.argtypes = [c_uint64]
    lib.isPrime.restype = c_uint64

    lib.factorizeAndPrint.argtypes = [c_uint64]
    lib.factorizeAndPrint.restype = None


    return lib


def main() -> None:
    lib = initLib()

    a,p,b = 25472862553,48600450361,41279512019
    # start = time.time()
    # logging.debug(pow(a,-1,p))
    # logging.debug(time.time()-start)
    lib.factorizeAndPrint(p-1)


    start = time.time()
    res = lib.dlp_spg(a,b,p)

    logging.debug(time.time()-start)
    logging.debug(res)

    assert pow(a, res, p) == b

    # # logging.debug("Starting bruteforce approach")
    # # result = lib.dlp_bruteforce(a, p, b)
    # # logging.debug(f"Result: {result}")

    # # assert lib.power(a, result, p) == b

    # # factors, powers = factor(p-1)
    # factors_ = sage_factor(p-1)
    # factors = [f[0] for f in factors_]
    # powers = [f[1] for f in factors_]
    # logging.debug(f"Factors: {factors}")
    # factors_ = (c_uint64 * len(factors))(*factors)
    # powers_ = (c_uint64 * len(powers))(*powers)

    # logging.debug(f"Starting spg approach, parameters:")
    # logging.debug(f"{a = }; {b = }; {p = };")
    # result = lib.dlp_spg(a, p, b, factors_, powers_, len(factors))

    # logging.debug(f"Result: {result}")
    # print("----------------")
    # result = SPG(a, b, p)
    # logging.debug(f"Result: {result}")

    # assert pow(a, result, p) == b   



if __name__ == "__main__":
    main()


