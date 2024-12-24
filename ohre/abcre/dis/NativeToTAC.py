from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.AsmTypes import AsmTypes
from ohre.abcre.dis.CODE_LV import CODE_LV
from ohre.abcre.dis.CodeBlocks import CodeBlocks
from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.NAC import NAC
from ohre.abcre.dis.TAC import TAC
from ohre.misc import Log, utils


class NativeToTAC:
    @classmethod
    def toTAC(cls, nac: NAC) -> TAC:
        print(f"toTAC: nac: {nac.debug_deep()}")  # TODO: more tac builder plz
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
        if (nac.op == "ldobjbyname"):
            return TAC.tac_assign(
                AsmArg(AsmTypes.ACC),
                AsmArg(AsmTypes.STR, value=nac.args[1]),
                log=f"arg0: {nac.args[0]} todo: check ldobjbyname")
        if (nac.op == "isfalse"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.FALSE), rop="==")
        if (nac.op == "callruntime.isfalse"):
            pass
        if (nac.op == "copyrestargs"):
            return TAC.tac_unknown([AsmArg(AsmTypes.IMM, value=nac.args[0])], log="todo: copyrestargs imm:u8")
        if (nac.op == "lda.str"):
            pass
        if (nac.op == "tryldglobalbyname"):
            pass

        if (nac.op == "stricteq"):
            pass
        if (nac.op == "ldundefined"):
            pass

        # === inst about jump START
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
        # === inst about jump END

        # === inst about call START
        if (nac.op == "callthis1"):
            pass
        if (nac.op == "callthisrange"):
            pass
        # === inst about call END

        # === inst about return START
        if (nac.op == "returnundefined"):
            pass
        if (nac.op == "return"):
            pass
        # === inst about return END

        Log.warn(f"toTAC failed, not support nac inst: {nac.debug_deep()}", False)  # to error when done
        return TAC.tac_unknown(
            [AsmArg(AsmTypes.UNKNOWN, nac.args[i]) for i in range(len(nac.args))],
            log=f"todo: {nac.op}")

    @classmethod
    def native_code_to_TAC(cls, blocks: CodeBlocks) -> CodeBlocks:
        assert blocks.level == CODE_LV.NATIVE_BLOCK_SPLITED
        cbs_l = list()
        for block in blocks.blocks:
            tac_inst_l = list()
            for nac_inst in block.insts:
                tac_inst = NativeToTAC.toTAC(nac_inst)  # TODO: may return a list of tac
                print(f"toTAC: tac: {tac_inst.debug_deep()}")
                tac_inst_l.append(tac_inst)
            cb = CodeBlock(tac_inst_l)
            cbs_l.append(cb)
        return CodeBlocks(cbs_l)
