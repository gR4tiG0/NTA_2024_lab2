#!/usr/bin/env python3
from ctypes import CDLL, c_uint64
import logging
from oracle import CliOracle, ServOracle

logging.basicConfig(level=logging.DEBUG)


LIB_NAME = "./libdlp.so"

def main() -> None:
    c_oracle = CliOracle()
    s_oracle = ServOracle()
    for digits in range(3, 12):
        c_oracle.start()
            
        a,b,p = c_oracle.getPartOne(digits)
        

        logging.debug(f"{a = }; {b = }; {p = };")
        result = s_oracle.getRes(a, b, p)
        logging.debug(f"Result: {result}")
        assert pow(a, result, p) == b
        logging.debug("Assertion confirmed, pow(a, r, b) == b")
        
        c_oracle.send(result)
        a,b,p = c_oracle.getPartTwo()

        logging.debug(f"{a = }; {b = }; {p = };")
        result = s_oracle.getRes(a, b, p)
        logging.debug(f"Result: {result}")
        assert pow(a, result, p) == b
        logging.debug("Assertion confirmed, pow(a, r, b) == b")
        
        c_oracle.send(result)

        c_oracle.close()


if __name__ == "__main__":
    main()
