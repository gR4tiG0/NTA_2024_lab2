#!/usr/bin/env python3
from ctypes import CDLL, c_uint64
from colorama import Fore, Style
from pwn import *
import logging
import time


LIB_NAME = "./libdlp.so"




class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors and custom prefixes"""

    FORMAT = {
        logging.DEBUG: Fore.WHITE + "[*] %(asctime)s - %(message)s" + Style.RESET_ALL,
        logging.INFO: Fore.BLUE + "[+] %(asctime)s - %(message)s" + Style.RESET_ALL,
        logging.WARNING: Fore.YELLOW + "[!] %(asctime)s - %(message)s" + Style.RESET_ALL,
        logging.ERROR: Fore.RED + "[!] %(asctime)s - %(message)s" + Style.RESET_ALL,
        logging.CRITICAL: Fore.RED + "[!] %(asctime)s - %(message)s" + Style.RESET_ALL
    }

    DATEFMT = '%Y-%m-%d %H:%M:%S'

    def format(self, record):
        log_fmt = self.FORMAT.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt=self.DATEFMT)
        return formatter.format(record)

logger = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
console_handler.setFormatter(CustomFormatter())
logger.addHandler(console_handler)
logger.setLevel(logging.DEBUG)

logging.getLogger('pwnlib').setLevel(logging.CRITICAL)


def initLib() -> CDLL:
    logger.debug(f"Initializing lib {LIB_NAME}")
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

class DockerOracle:
    def __init__(self, lib) -> None:
        self.lib = lib
        self.command = ['docker', 'run', '-i', 'salo1d/nta_cp2_helper:2.0']
        self.ok_word = "BINGO" 
    
    def startCommunication(self, dec_len:int, second_step:bool = True) -> None:
        logger.info(f"Starting communication with oracle with dec_len = {dec_len}")
        r = process(self.command)
        r.recvuntil(b': ')
        r.sendline(str(dec_len).encode())
        inp = r.recvuntil(b'value: ')
        a,b,p = self.oracleParseInput(inp)
        logger.debug(f"Received a = {a}, b = {b}, p = {p}")
        logger.debug(f"Starting SPH")

        start = time.time()
        res = self.lib.dlp_spg(a,b,p)
        logger.info(f"Time taken: {time.time()-start}")
        logger.debug(f"Result {res}")
        assert pow(a, res, p) == b
        logger.info(f"SPH passed, sending result to oracle")

        r.sendline(str(res).encode())
        inp = r.recvuntil(b'value: ')
        if self.ok_word not in inp.decode():
            logger.error(f"Oracle failed to validate SPH result")
            exit(1)
        
        logger.debug(f"Oracle validated SPH result")

        if second_step:
            logger.info(f"Starting Task 2")
            a,b,p = self.oracleParseInput(inp)
            logger.debug(f"Received a = {a}, b = {b}, p = {p}")
            logger.debug(f"Starting SPH")

            start = time.time()
            res = self.lib.dlp_spg(a,b,p)
            logger.info(f"Time taken: {time.time()-start}")
            logger.debug(f"Result {res}")
            assert pow(a, res, p) == b
            logger.info(f"SPH passed, sending result to oracle")

            r.sendline(str(res).encode())
            inp = r.recvuntil(b'closed')
            if self.ok_word not in inp.decode():
                logger.error(f"Oracle failed to validate SPH result")
                exit(1)
            
            logger.debug(f"Oracle validated SPH result")

        r.close()

    def oracleParseInput(self, inp: bytes) -> tuple:
        inp = inp.decode().strip().split(";")
        a = int(inp[0][1:].split("= ")[-1])
        b = int(inp[1][1:].split("= ")[-1])
        p = int(inp[2][1:].split("= ")[-1].split(".")[0])
        
        return a,b,p

def main() -> None:
    lib = initLib()

    oracle = DockerOracle(lib)
    
    for i in range(10, 21):
        try:
            if i > 12:
                oracle.startCommunication(i, False)
            else:
                oracle.startCommunication(i)
        except Exception as e:
            logger.error(f"Exception: {e}")
            continue
    

if __name__ == "__main__":
    main()


