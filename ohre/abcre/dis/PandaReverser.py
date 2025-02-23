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

    def split_native_code_block(self, module_name: str = None, method_name: str = None) -> bool:
        meth = self.dis_file.get_meth(module_name, method_name)
        if (meth is None):
            print(f"d3bug {self.dis_file.methods.keys()} || {self.dis_file.methods[module_name].keys()}")
            Log.error(f"split cbs paras NOT valid: module_name {module_name} method_name {method_name}")
            return False
        if (meth.level != CODE_LV.NATIVE):
            Log.error(f"split_native_code_block: code level NOT valid, {module_name} {method_name} is {meth.level_str}")
            return False
        meth.split_native_code_block()
        meth.set_level(CODE_LV.NATIVE_BLOCK_SPLITED)
        return True

    def trans_NAC_to_TAC(self, module_name: str = None, method_name: str = None) -> bool:
        meth = self.dis_file.get_meth(module_name, method_name)
        if (meth is None):
            Log.error(f"to tac paras NOT valid: module_name {module_name} method_name {method_name}")
            return False
        if (meth.level != CODE_LV.NATIVE_BLOCK_SPLITED):
            Log.error(f"trans_NAC_to_TAC: code level NOT valid, {module_name} {method_name} is {meth.level_str}")
            return False
        NACtoTAC.trans_NAC_to_TAC(meth, self.dis_file)
        meth.set_level(CODE_LV.TAC)
        return True

    def get_tac_unknown_count(self) -> int:
        cnt = 0
        unknown_opcode = set()
        for _, name_meth_d in self.dis_file.methods.items():
            for _, meth in name_meth_d.items():
                for cb in meth.code_blocks:
                    for inst in cb.insts:
                        if (inst.type == TACTYPE.UNKNOWN):
                            cnt += 1
                            unknown_opcode.add(inst.args[0])
        return cnt, unknown_opcode

    def get_insts_total(self) -> int:
        cnt = 0
        for _, d in self.dis_file.methods.items():
            for _, meth in d.items():
                cnt += meth.get_insts_total()
        return cnt

    def _code_lifting_algorithms(self, module_name: str = None, method_name: str = None) -> bool:  # method_id: int = -1
        meth = self.dis_file.get_meth(module_name, method_name)
        if (meth is None):
            Log.error(f"lifting paras NOT valid: module_name {module_name} method_name {method_name}")
            return False
        if (meth.level != CODE_LV.TAC):
            Log.error(f"lifting: code level NOT valid, {module_name} {method_name} is {meth.level_str}")
            return False
        meth._insert_variable_virtual_block()
        print(f"_code_lifting_algorithms START {meth.module_method_name} inst-{meth.inst_len}")
        old_insts_len, new_insts_len = -1, -2
        while (old_insts_len > new_insts_len):
            old_insts_len = meth.get_insts_total()
            PeepholeOptimization(meth)
            if (old_insts_len == meth.get_insts_total()):
                break
            DeadCodeElimination(meth)
            new_insts_len = meth.get_insts_total()

        print(f"_code_lifting_algorithms MID {meth.module_method_name} inst-{meth.inst_len}")

        old_insts_len, new_insts_len = -1, -2
        while (old_insts_len > new_insts_len):
            old_insts_len = meth.get_insts_total()
            CopyPropagation(meth)
            DeadCodeElimination(meth)
            PeepholeOptimization(meth)
            new_insts_len = meth.get_insts_total()
        DeadCodeElimination(meth)
        print(f"_code_lifting_algorithms END {meth.module_method_name} inst-{meth.inst_len}")
        meth.set_level(CODE_LV.IR_LIFTED)
        return True

    def _module_analysis_algorithms(self):
        for module_name, name_meth_d in self.dis_file.methods.items():
            for method_name, meth in name_meth_d.items():
                if (meth.level == CODE_LV.NATIVE):
                    self.split_native_code_block(module_name, method_name)
                if (meth.level == CODE_LV.NATIVE_BLOCK_SPLITED):
                    self.trans_NAC_to_TAC(module_name, method_name)
                if (meth.level == CODE_LV.TAC):
                    self._code_lifting_algorithms(module_name, method_name)
        ModuleVarAnalysis(self.dis_file)

    def method_len(self) -> int:
        return self.dis_file.method_len()

    def get_meth(self, module_name: str = None, method_name: str = None,
                 module_method_name: str = None) -> Union[AsmMethod, None]:
        return self.dis_file.get_meth(module_name, method_name, module_method_name)

    def _debug_str(self) -> str:
        out = f"PandaReverser: {self.dis_file}"
        return out

    def _debug_vstr(self) -> str:
        out = f"{self._debug_str()}\n"
        return out
