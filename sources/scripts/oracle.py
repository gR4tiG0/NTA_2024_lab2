from colorama import Fore, Style
import logging
from pwn import *
import time

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

ANSWER = 4
STEP_ONE = 5
STEP_TWO = 6

class CliOracle:
    def __init__(self):
        self.command = ['docker', 'run', '-i', '--rm', 'salo1d/nta_cp2_helper:2.0']
        self.ok_word = "BINGO" 

        self.part = STEP_ONE
        self.state = STEP_ONE
        self.r = None
        
    def start(self) -> None:
        self.r = process(self.command)

    def close(self) -> None:
        self.r.close()
    
    def getPartOne(self, dec_len:int) -> list:
        if self.state != STEP_ONE:
            logger.error("Invalid state")
            return []
        logger.info(f"Starting communication with oracle with dec_len = {dec_len}")
        
        self.r.recvuntil(b': ')
        self.r.sendline(str(dec_len).encode())
        inp = self.r.recvuntil(b'value: ')
        a,b,p = self.oracleParseInput(inp)
        
        logger.debug(f"Received a = {a}, b = {b}, p = {p}")
        self.part = STEP_TWO
        self.state = ANSWER
        return [a,b,p]

        

    def getPartTwo(self) -> list:
        if self.state != STEP_TWO:
            logger.error("Invalid state")
            return []
        
        logger.info(f"Starting Task 2")
        inp = self.r.recvuntil(b': x = ')
        a,b,p = self.oracleParseInput(inp)
        logger.debug(f"Received a = {a}, b = {b}, p = {p}")
        
        self.part = STEP_ONE
        self.state = ANSWER

        return [a,b,p]
    

    def oracleParseInput(self, inp: bytes) -> tuple:
        inp = inp.decode().strip().split(";")
        a = int(inp[0][1:].split("= ")[-1])
        b = int(inp[1][1:].split("= ")[-1])
        p = int(inp[2][1:].split("= ")[-1].split(".")[0])
        
        return a,b,p
    
    def send(self, res: int) -> None:
        if self.state != ANSWER:
            logger.error("Invalid state")
            return
        self.r.sendline(str(res).encode())
        inp = self.r.recvline()
        if self.ok_word not in inp.decode():
            logger.error(f"Oracle failed to validate SPH result")
            exit(1)
        
        logger.debug(f"Oracle validated SPH result")
        self.state = self.part



class ServOracle:
    def __init__(self):
        self.command = ['docker', 'run', '--rm', '-i', 'nta_lab2']
    
    def getRes(self, a:int, b:int, p:int, mode:str="SPH") -> int:
        r = process(self.command)
        r.sendlineafter(b'> ', mode.encode())
        r.sendlineafter(b'a = ', str(a).encode())
        r.sendlineafter(b'b = ', str(b).encode())
        r.sendlineafter(b'p = ', str(p).encode())
        logger.info(r.recvline().decode())  
        res = int(r.recvline().decode().split(" = ")[1])    
        r.close()
        return res