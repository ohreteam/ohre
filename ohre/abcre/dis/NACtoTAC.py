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
from ohre.abcre.dis.NACTYPE import NACTYPE
from ohre.misc import Log, utils


class NACtoTAC:
    @classmethod
    def toTAC(self, nac: NAC, asm_method: AsmMethod, dis_file: DisFile) -> Union[TAC, List[TAC]]:
        print(f"nac_: {nac._debug_vstr()}")  # TODO: more tac builder plz
        if (nac.type == NACTYPE.LABEL):
            return TAC.tac_label(AsmArg(AsmTypes.LABEL, nac.op))

        if (nac.op == "mov"):
            return TAC.tac_assign(AsmArg.build_arg(nac.args[0]), AsmArg.build_arg(nac.args[1]))
        if (nac.op == "lda"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[0]))
        if (nac.op == "lda.str"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.STR, value=nac.args[0]))
        if (nac.op == "ldai"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.IMM, value=nac.args[0]))
        if (nac.op == "ldtrue"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.TRUE))
        if (nac.op == "ldfalse"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.FALSE))
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
        if (nac.op == "neg"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), rop="-")
        # === inst: unary operations # END

        # === inst: binary operations # START
        if (nac.op == "eq"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[1]), rop="==")
        # === inst: binary operations # END

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
        if (nac.op == "callarg1"):
            return TAC.tac_call(
                arg_len=AsmArg(AsmTypes.IMM, value=1),
                paras=[AsmArg.build_arg(nac.args[1])],
                log="todo: add acc=ret after this")
        if (nac.op == "callargs2"):
            return TAC.tac_call(
                arg_len=AsmArg(AsmTypes.IMM, value=2),
                paras=[AsmArg.build_arg(nac.args[1]), AsmArg.build_arg(nac.args[2])],
                log="todo: add acc=ret after this")
        if (nac.op == "callargs3"):
            return TAC.tac_call(
                arg_len=AsmArg(AsmTypes.IMM, value=3),
                paras=[AsmArg.build_arg(nac.args[1]), AsmArg.build_arg(nac.args[2]), AsmArg.build_arg(nac.args[3])],
                log="todo: add acc=ret after this")
        if (nac.op == "callthisrange"):
            # callthisrange reserved, para_cnt, this_ptr # acc: method obj # para(cnt): this_ptr para0 ...
            arg_len = int(nac.args[1], 16)
            paras_l = list()
            this_p = AsmArg.build_arg(nac.args[2])
            arg = this_p
            for i in range(arg_len):
                arg = arg.build_next_arg()
                paras_l.append(arg)
            return TAC.tac_call(
                arg_len=AsmArg(AsmTypes.IMM, value=arg_len),
                paras=paras_l,
                this=this_p)
        # === inst: call instructions # END

        # === inst: dynamic return # START
        if (nac.op == "returnundefined"):
            return TAC.tac_return(AsmArg(AsmTypes.UNDEFINED))
        if (nac.op == "return"):
            return TAC.tac_return(AsmArg(AsmTypes.ACC))
        # === inst: dynamic return # END

        # === inst: object visitors # START
        if (nac.op == "ldobjbyname"):
            return TAC.tac_assign(
                AsmArg(AsmTypes.ACC),
                AsmArg(AsmTypes.STR, value=nac.args[1]),
                log=f"arg0: {nac.args[0]} todo: check ldobjbyname")
        if (nac.op == "tryldglobalbyname"):
            return TAC.tac_assign(
                AsmArg(AsmTypes.ACC),
                AsmArg(AsmTypes.STR, value=nac.args[1]),
                log=f"arg0: {nac.args[0]} todo: check tryldglobalbyname, not throw now")
        if (nac.op == "ldexternalmodulevar"):
            index = int(nac.args[0], base=16)
            module_name = dis_file.get_external_module_name(index, asm_method.file_name, asm_method.class_method_name)
            if (module_name is not None and len(module_name) > 0):
                asm_method.set_cur_module(module_name)
                return TAC.tac_import(AsmArg(AsmTypes.MODULE, name=module_name))
            else:
                asm_method.set_cur_module("module load failed")
        if (nac.op == "copyrestargs"):
            return TAC.tac_unknown([AsmArg(AsmTypes.IMM, value=nac.args[0])], log="todo: copyrestargs imm:u8")
        # === inst: object visitors # END

# === inst: definition instuctions # START
        if (nac.op == "definefunc"):
            return TAC.tac_assign(
                AsmArg(AsmTypes.ACC),
                AsmArg(AsmTypes.METHOD_OBJ, value=nac.args[1], paras_len=int(nac.args[2], 16)))
        # === inst: definition instuctions # END

        Log.warn(f"toTAC failed, not support nac inst: {nac._debug_vstr()}", False)  # to error when done
        return TAC.tac_unknown(
            [AsmArg(AsmTypes.UNKNOWN, nac.args[i]) for i in range(len(nac.args))],
            log=f"todo: {nac.op}")

    @classmethod
    def trans_NAC_to_TAC(cls, asm_method: AsmMethod, dis_file: DisFile) -> CodeBlocks:
        cbs = asm_method.code_blocks
        assert cbs.level == CODE_LV.NATIVE_BLOCK_SPLITED
        cbs_l = list()
        for block in cbs.blocks:
            tac_inst_l = list()
            for nac_inst in block.insts:
                tac_inst = NACtoTAC.toTAC(nac_inst, asm_method, dis_file)  # TODO: may return a list of tac
                print(f"tac^: {tac_inst._debug_vstr()}")
                tac_inst_l.append(tac_inst)
            cb = CodeBlock(tac_inst_l)
            cbs_l.append(cb)
        return CodeBlocks(cbs_l)
