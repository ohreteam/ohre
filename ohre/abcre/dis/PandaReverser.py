from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.AsmRecord import AsmRecord
from ohre.abcre.dis.AsmString import AsmString
from ohre.abcre.dis.AsmTypes import AsmTypes
from ohre.abcre.dis.CodeBlocks import CodeBlocks
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.abcre.dis.DisFile import DisFile
from ohre.abcre.dis.NACtoTAC import NACtoTAC
from ohre.misc import Log, utils


class PandaReverser(DebugBase):
    # interface class for user
    def __init__(self, dis_file: DisFile):
        self.dis_file: DisFile = dis_file

    def split_native_code_block(self, method_id: int = -1, method_name: str = None):
        if (isinstance(method_id, int) and method_id >= 0 and method_id < len(self.dis_file.methods)):
            self.dis_file.methods[method_id].split_native_code_block()
        elif (method_name is not None and len(method_name)):
            pass
        else:
            pass

    def trans_NAC_to_TAC(self, method_id: int = -1, method_name: str = None):
        if (isinstance(method_id, int) and method_id >= 0 and method_id < len(self.dis_file.methods)):
            cbs = NACtoTAC.trans_NAC_to_TAC(self.dis_file.methods[method_id], self.dis_file)
        elif (method_name is not None and len(method_name)):
            pass
        else:
            pass

    def method_len(self):
        return len(self.dis_file.methods)

    def _debug_str(self) -> str:
        out = f"PandaReverser: {self.dis_file}"
        return out

    def _debug_vstr(self) -> str:
        out = f"{self._debug_str()}\n"
        return out
