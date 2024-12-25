import copy
from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.AsmTypes import AsmTypes
from ohre.abcre.dis.CODE_LV import CODE_LV
from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.CodeBlocks import CodeBlocks
from ohre.abcre.dis.DisFile import DisFile
from ohre.abcre.dis.NAC import NAC
from ohre.abcre.dis.TAC import TAC
from ohre.misc import Log, utils


class NACtoTAC:
    @classmethod
    def toTAC(self, nac: NAC, ams_method: AsmMethod, dis_file: DisFile) -> Union[TAC, List[TAC]]:
        print(f"nac_: {nac._debug_vstr()}")  # TODO: more tac builder plz

        if (nac.op == "mov"):
            return TAC.tac_assign(AsmArg.build_arg(nac.args[0]), AsmArg.build_arg(nac.args[1]))
        if (nac.op == "lda"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[0]))
        if (nac.op == "lda.str"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.STR, value=nac.args[0]))
        if (nac.op == "ldai"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.IMM, value=nac.args[0]))
        if (nac.op == "ldnull"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.NULL))
        if (nac.op == "ldundefined"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.UNDEFINED))
        if (nac.op == "sta"):
            return TAC.tac_assign(AsmArg.build_arg(nac.args[0]), AsmArg(AsmTypes.ACC))
        if (nac.op == "callruntime.isfalse"):
            pass
        if (nac.op == "lda.str"):
            pass
        if (nac.op == "ldundefined"):
            pass
        # === inst: comparation instructions # START
        if (nac.op == "stricteq"):
            pass
        # === inst: comparation instructions # END

        # === inst: unary operations # START
        if (nac.op == "isfalse"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.FALSE), rop="==")
        if (nac.op == "istrue"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.TRUE), rop="==")
        # === inst: unary operations # END

        # === inst: jump operations # START
        if (nac.op == "jnez"):  # TODO: jnez imm:i32 # a label str in *.dis file # support imm in future
            return TAC.tac_cond_jmp(
                AsmArg(AsmTypes.LABEL, nac.args[0]),
                AsmArg(AsmTypes.ZERO),
                AsmArg(AsmTypes.ACC),
                "!=")
        if (nac.op == "jeqz"):  # TODO: jeqz imm:i32 # a label str in *.dis file # support imm in future
            return TAC.tac_cond_jmp(
                AsmArg(AsmTypes.LABEL, nac.args[0]),
                AsmArg(AsmTypes.ZERO),
                AsmArg(AsmTypes.ACC),
                "==")
        if (nac.op == "jmp"):
            return TAC.tac_uncn_jmp(AsmArg(AsmTypes.LABEL, nac.args[0]), log="todo: check label's existence")
        # === inst: jump operations # END

        # === inst: call instructions # START
        if (nac.op == "callthis1"):
            pass
        if (nac.op == "callthisrange"):
            pass
        # === inst: call instructions # END

        # === inst: dynamic return # START
        if (nac.op == "returnundefined"):
            pass
        if (nac.op == "return"):
            pass
        # === inst: dynamic return # END

        # === inst: object visitors # START
        if (nac.op == "ldobjbyname"):
            return TAC.tac_assign(
                AsmArg(AsmTypes.ACC),
                AsmArg(AsmTypes.STR, value=nac.args[1]),
                log=f"arg0: {nac.args[0]} todo: check ldobjbyname")
        if (nac.op == "ldexternalmodulevar"):
            pass
        if (nac.op == "tryldglobalbyname"):
            pass
        if (nac.op == "copyrestargs"):
            return TAC.tac_unknown([AsmArg(AsmTypes.IMM, value=nac.args[0])], log="todo: copyrestargs imm:u8")
        # === inst: object visitors # END

        Log.warn(f"toTAC failed, not support nac inst: {nac._debug_vstr()}", False)  # to error when done
        return TAC.tac_unknown(
            [AsmArg(AsmTypes.UNKNOWN, nac.args[i]) for i in range(len(nac.args))],
            log=f"todo: {nac.op}")

    @classmethod
    def trans_NAC_to_TAC(cls, ams_method: AsmMethod, dis_file: DisFile) -> CodeBlocks:
        cbs = ams_method.code_blocks
        assert cbs.level == CODE_LV.NATIVE_BLOCK_SPLITED
        cbs_l = list()
        for block in cbs.blocks:
            tac_inst_l = list()
            for nac_inst in block.insts:
                tac_inst = NACtoTAC.toTAC(nac_inst, ams_method, dis_file)  # TODO: may return a list of tac
                print(f"tac^: {tac_inst._debug_vstr()}")
                tac_inst_l.append(tac_inst)
            cb = CodeBlock(tac_inst_l)
            cbs_l.append(cb)
        return CodeBlocks(cbs_l)
