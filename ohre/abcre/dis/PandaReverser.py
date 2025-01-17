from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.AsmRecord import AsmRecord
from ohre.abcre.dis.AsmString import AsmString
from ohre.abcre.dis.CodeBlocks import CodeBlocks
from ohre.abcre.dis.DebugBase import DebugBase
from ohre.abcre.dis.DisFile import DisFile
from ohre.abcre.dis.enum.AsmTypes import AsmTypes
from ohre.abcre.dis.enum.CODE_LV import CODE_LV
from ohre.abcre.dis.enum.TACTYPE import TACTYPE
from ohre.abcre.dis.lifting.CopyPropagation import CopyPropagation
from ohre.abcre.dis.lifting.DeadCodeElimination import DeadCodeElimination
from ohre.abcre.dis.lifting.PeepholeOptimization import PeepholeOptimization
from ohre.abcre.dis.NACtoTAC import NACtoTAC
from ohre.misc import Log, utils


class PandaReverser(DebugBase):
    # interface class for user
    def __init__(self, dis_file: DisFile):
        self.dis_file: DisFile = dis_file

    def split_native_code_block(self, method_id: int = -1, method_name: str = None) -> bool:
        if (isinstance(method_id, int) and method_id >= 0 and method_id < len(self.dis_file.methods)):
            self.dis_file.methods[method_id].split_native_code_block()
            self.dis_file.methods[method_id].set_level(CODE_LV.NATIVE_BLOCK_SPLITED)
            return True
        elif (method_name is not None and len(method_name)):
            pass
        Log.error(f"split cbs paras NOT valid: method_id {method_id} method_name {method_name}")

    def trans_NAC_to_TAC(self, method_id: int = -1, file_class_method_name: str = None):
        if (isinstance(method_id, int) and method_id >= 0 and method_id < len(self.dis_file.methods)):
            NACtoTAC.trans_NAC_to_TAC(self.dis_file.methods[method_id], self.dis_file)
            self.dis_file.methods[method_id].set_level(CODE_LV.TAC)
            return True
        elif (file_class_method_name is not None and len(file_class_method_name) > 0):
            pass
        Log.error(f"to tac paras NOT valid: method_id {method_id} file_class_method_name {file_class_method_name}")

    def get_tac_unknown_count(self):
        cnt = 0
        for met in self.dis_file.methods:
            for cb in met.code_blocks:
                for inst in cb.insts:
                    if (inst.type == TACTYPE.UNKNOWN):
                        cnt += 1
        return cnt

    def get_insts_total(self):
        cnt = 0
        for met in self.dis_file.methods:
            cnt += met.get_insts_total()
        return cnt

    def _code_lifting_algorithms(self, method_id: int = -1):
        if (isinstance(method_id, int) and method_id >= 0 and method_id < len(self.dis_file.methods)):
            meth = self.dis_file.methods[method_id]
            meth._insert_variable_virtual_block()
            print(
                f"\n_code_lifting_algorithms START {meth.name}, inst total {meth.get_insts_total()}: {meth._debug_vstr()}")
            old_insts_len, new_insts_len = -1, 0
            while (old_insts_len != new_insts_len):
                old_insts_len = meth.get_insts_total()
                DeadCodeElimination(meth)
                PeepholeOptimization(meth)
                new_insts_len = meth.get_insts_total()

            debug_out = f""
            for cb in meth.code_blocks:
                debug_out += f" {cb}"
            print(f"_code_lifting_algorithms MID-END {debug_out}, inst total {meth.get_insts_total()}")

            old_insts_len, new_insts_len = -1, 0
            while (old_insts_len != new_insts_len):
                old_insts_len = meth.get_insts_total()
                CopyPropagation(meth)
                DeadCodeElimination(meth)
                PeepholeOptimization(meth)
                new_insts_len = meth.get_insts_total()
            DeadCodeElimination(meth)
            debug_out = f""
            for cb in meth.code_blocks:
                debug_out += f" {cb}"
            print(f"_code_lifting_algorithms END {debug_out}, inst total {meth.get_insts_total()}")

    def method_len(self):
        return len(self.dis_file.methods)

    def _debug_str(self) -> str:
        out = f"PandaReverser: {self.dis_file}"
        return out

    def _debug_vstr(self) -> str:
        out = f"{self._debug_str()}\n"
        return out
