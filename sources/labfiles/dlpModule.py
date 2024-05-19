from ctypes import CDLL, c_uint64

class DLPSolver:
    def __init__(self):
        self.lib_name = "./libdlp.so"
        self.lib = self.initLib()

    def initLib(self) -> CDLL:
        lib = CDLL(self.lib_name)
        lib.dlp_bruteforce.argtypes = [c_uint64, c_uint64, c_uint64]
        lib.dlp_bruteforce.restype = c_uint64

        lib.dlp_sph.argtypes = [c_uint64, c_uint64, c_uint64]
        lib.dlp_sph.restype = c_uint64

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
    
    def dlp_bruteforce(self, a:int, b:int, p:int) -> int:
        return self.lib.dlp_bruteforce(a, b, p)
    
    def dlp_sph(self, a:int, b:int, p:int) -> int:
        return self.lib.dlp_sph(a, b, p)