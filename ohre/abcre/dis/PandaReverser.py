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
from ohre.abcre.dis.lifting.ModuleVarAnalysis import ModuleVarAnalysis
from ohre.abcre.dis.lifting.PeepholeOptimization import PeepholeOptimization
from ohre.abcre.dis.NACtoTAC import NACtoTAC
from ohre.misc import Log, utils


class PandaReverser(DebugBase):
    # interface class for user
    def __init__(self, dis_file: DisFile):
        self.dis_file: DisFile = dis_file

    @property
    def dis_name(self) -> str:
        return self.dis_file.dis_name

    def split_native_code_block(self, method_id: int = -1, method_name: str = None) -> bool:
        if (isinstance(method_id, int) and method_id >= 0 and method_id < len(self.dis_file.methods)):
            self.dis_file.methods[method_id].split_native_code_block()
            self.dis_file.methods[method_id].set_level(CODE_LV.NATIVE_BLOCK_SPLITED)
            return True
        elif (method_name is not None and len(method_name)):
            pass
        Log.error(f"split cbs paras NOT valid: method_id {method_id} method_name {method_name}")
        return False

    def trans_NAC_to_TAC(self, method_id: int = -1, file_class_method_name: str = None) -> bool:
        if (isinstance(method_id, int) and method_id >= 0 and method_id < len(self.dis_file.methods)):
            meth = self.dis_file.methods[method_id]
            if (meth.level != CODE_LV.NATIVE_BLOCK_SPLITED):
                Log.error(f"trans_NAC_to_TAC: code level NOT valid, method[{method_id}] is {meth.level_str}")
                return False
            NACtoTAC.trans_NAC_to_TAC(meth, self.dis_file)
            meth.set_level(CODE_LV.TAC)
            return True
        elif (file_class_method_name is not None and len(file_class_method_name) > 0):
            pass
        Log.error(f"to tac paras NOT valid: method_id {method_id} file_class_method_name {file_class_method_name}")
        return False

    def get_tac_unknown_count(self) -> int:
        cnt = 0
        unknown_opcode = set()
        for met in self.dis_file.methods:
            for cb in met.code_blocks:
                for inst in cb.insts:
                    if (inst.type == TACTYPE.UNKNOWN):
                        cnt += 1
                        unknown_opcode.add(inst.args[0])
        return cnt, unknown_opcode

    def get_insts_total(self) -> int:
        cnt = 0
        for met in self.dis_file.methods:
            cnt += met.get_insts_total()
        return cnt

    def _code_lifting_algorithms(self, method_id: int = -1) -> bool:
        if (isinstance(method_id, int) and method_id >= 0 and method_id < len(self.dis_file.methods)):
            meth = self.dis_file.methods[method_id]
            if (meth.level != CODE_LV.TAC):
                Log.error(f"code level NOT valid, method[{method_id}] is {meth.level_str}")
                return False
            meth._insert_variable_virtual_block()
            print(f"_code_lifting_algorithms START {method_id} {meth.name} inst-{meth.inst_len}\n{meth._debug_vstr()}")
            old_insts_len, new_insts_len = -1, 0
            while (old_insts_len != new_insts_len):
                old_insts_len = meth.get_insts_total()
                DeadCodeElimination(meth)
                PeepholeOptimization(meth)
                new_insts_len = meth.get_insts_total()

            print(f"_code_lifting_algorithms MID {method_id} {meth.name} inst-{meth.inst_len}\n{meth._debug_vstr()}")

            old_insts_len, new_insts_len = -1, 0
            while (old_insts_len != new_insts_len):
                old_insts_len = meth.get_insts_total()
                CopyPropagation(meth)
                DeadCodeElimination(meth)
                PeepholeOptimization(meth)
                new_insts_len = meth.get_insts_total()
            DeadCodeElimination(meth)
            print(f"_code_lifting_algorithms END {method_id} {meth.name} inst-{meth.inst_len}\n{meth._debug_vstr()}")
            meth.set_level(CODE_LV.IR_LIFTED)
            return True
        else:
            Log.error(f"_code_lifting_algorithms method_id NOT valid: {method_id}")
            return False

    def _module_analysis_algorithms(self):
        for method_id in range(len(self.dis_file.methods)):
            if (self.dis_file.methods[method_id].level == CODE_LV.NATIVE):
                self.split_native_code_block(method_id=method_id)
            if (self.dis_file.methods[method_id].level == CODE_LV.NATIVE_BLOCK_SPLITED):
                self.trans_NAC_to_TAC(method_id=method_id)
            if (self.dis_file.methods[method_id].level == CODE_LV.TAC):
                self._code_lifting_algorithms(method_id)
        ModuleVarAnalysis(self.dis_file)

    def method_len(self) -> int:
        return len(self.dis_file.methods)

    def _debug_str(self) -> str:
        out = f"PandaReverser: {self.dis_file}"
        return out

    def _debug_vstr(self) -> str:
        out = f"{self._debug_str()}\n"
        return out
