from ohre.abcre.dis.NAC import NAC
from ohre.abcre.dis.TAC import TAC
from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.CODE_LV import CODE_LV
from ohre.abcre.dis.CodeBlocks import CodeBlocks
from ohre.abcre.dis.AsmTypes import AsmTypes
from ohre.misc import Log, utils


class NativeToTAC:
    @classmethod
    def toTAC(cls, nac: NAC) -> TAC:
        print(f"toTAC: nac: {nac.debug_deep()}") # TODO: more tac builder plz
        if (nac.op == "mov"):  # mov v1:out:any, v2:in:any # mov v0, a0
            return TAC.tac_assign(AsmArg.build_arg(nac.args[0]), AsmArg.build_arg(nac.args[1]))
        if (nac.op == "lda"):  # lda v:in:any # lda v8
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[0]))
        if (nac.op == "sta"):  # sta v:out:any # sta v6
            return TAC.tac_assign(AsmArg.build_arg(nac.args[0]), AsmArg(AsmTypes.ACC))
        if (nac.op == "ldobjbyname"):  # ldobjbyname imm:u16, string_id # ldobjbyname 0x0, "code"
            return TAC.tac_assign(
                AsmArg(AsmTypes.ACC),
                AsmArg(AsmTypes.ACC, "", nac.args[1]),
                log=f"arg0: {nac.args[0]} ")
        if (nac.op == "isfalse"):  # acc = ecma_op(acc, operand_0, ..., operands_n)
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.FALSE), rop="==")
        if (nac.op == "jnez"):  # jnez imm:i32 # a label str in *.dis file
            return TAC.tac_assign()
        else:
            Log.error(f"toTAC failed, not support nac inst: {nac.debug_deep()}")
            return None

    @classmethod
    def native_code_to_TAC(cls, blocks: CodeBlocks) -> CodeBlocks:
        assert blocks.level == CODE_LV.NATIVE_BLOCK_SPLITED
        for block in blocks.blocks:
            for nac_inst in block.insts:
                tac_inst = NativeToTAC.toTAC(nac_inst)
                print(f"toTAC: tac: {tac_inst.debug_deep()}")
