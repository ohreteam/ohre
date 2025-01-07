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
from ohre.abcre.dis.NACTYPE import NACTYPE
from ohre.abcre.dis.TAC import TAC
from ohre.misc import Log, utils


class NACtoTAC:
    @classmethod
    def toTAC(self, nac: NAC, asm_method: AsmMethod, dis_file: DisFile) -> Union[TAC, List[TAC]]:
        print(f"nac_: {nac._debug_vstr()}")  # TODO: more tac builder plz
        if (nac.type == NACTYPE.LABEL):
            return TAC.tac_label(AsmArg(AsmTypes.LABEL, nac.op))

        if (nac.op == "mov"):  # Dynamic move register-to-register
            return TAC.tac_assign(AsmArg.build_arg(nac.args[0]), AsmArg.build_arg(nac.args[1]))
        if (nac.op == "lda"):  # Dynamic load accumulator from register
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[0]))
        if (nac.op == "lda.str"):  # Load accumulator from string constant pool
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.STR, value=nac.args[0]))
        if (nac.op == "ldai"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.IMM, value=nac.args[0]))
        if (nac.op == "fldai"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.IMM, value=nac.args[0]))
        if (nac.op == "sta"):  # Dynamic store accumulator
            return TAC.tac_assign(AsmArg.build_arg(nac.args[0]), AsmArg(AsmTypes.ACC))

        # === inst: constant object loaders # START
        if (nac.op == "ldnan"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.NAN))
        if (nac.op == "ldinfinity"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.INF))
        if (nac.op == "ldtrue"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.TRUE))
        if (nac.op == "ldfalse"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.FALSE))
        if (nac.op == "ldhole"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.HOLE))
        if (nac.op == "ldnull"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.NULL))
        if (nac.op == "ldundefined"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.UNDEFINED))
        # === inst: constant object loaders # END

        # === inst: comparation instructions # START
        if (nac.op == "isin"):
            return TAC.tac_assign(
                AsmArg(AsmTypes.ACC),
                AsmArg.build_arg(nac.args[1]),
                AsmArg(AsmTypes.ACC),
                rop="in", log=f"arg0 {nac.args[0]}")
        if (nac.op == "instanceof"):
            return TAC.tac_assign(
                AsmArg(AsmTypes.ACC),
                AsmArg.build_arg(nac.args[1]),
                AsmArg(AsmTypes.ACC),
                rop="instanceof", log=f"instanceof {nac.args[0]}")
        if (nac.op == "stricteq"):
            return TAC.tac_assign(
                AsmArg(AsmTypes.ACC),
                AsmArg(AsmTypes.ACC),
                AsmArg.build_arg(nac.args[1]),
                rop="===", log=f"stricteq arg0 {nac.args[0]}")
        if (nac.op == "strictnoteq"):
            return TAC.tac_assign(
                AsmArg(AsmTypes.ACC),
                AsmArg(AsmTypes.ACC),
                AsmArg.build_arg(nac.args[1]),
                rop="!==", log=f"strictnoteq arg0 {nac.args[0]}")
        # === inst: comparation instructions # END

        # === inst: unary operations # START
        if (nac.op == "isfalse"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.FALSE), rop="==")
        if (nac.op == "istrue"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.TRUE), rop="==")
        if (nac.op == "neg"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), rop="-")
        if (nac.op == "deprecated.neg"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), rop="-")
        if (nac.op == "inc"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.IMM, value=1), rop="+")
        if (nac.op == "deprecated.inc"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.IMM, value=1), rop="+")
        if (nac.op == "dec"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.IMM, value=1), rop="-")
        if (nac.op == "deprecated.dec"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.IMM, value=1), rop="-")
        # === inst: unary operations # END

        # === inst: binary operations # START
        if (nac.op == "eq"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[1]), rop="==")
        if (nac.op == "noteq"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[1]), rop="!=")
        if (nac.op == "less"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[1]), AsmArg(AsmTypes.ACC), rop="<")
        if (nac.op == "lesseq"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[1]), AsmArg(AsmTypes.ACC), rop="<=")
        if (nac.op == "greater"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[1]), AsmArg(AsmTypes.ACC), rop=">")
        if (nac.op == "greatereq"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[1]), AsmArg(AsmTypes.ACC), rop=">=")

        if (nac.op == "add2"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[1]), AsmArg(AsmTypes.ACC), rop="+")
        if (nac.op == "sub2"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[1]), AsmArg(AsmTypes.ACC), rop="-")
        if (nac.op == "mul2"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[1]), AsmArg(AsmTypes.ACC), rop="*")
        if (nac.op == "div2"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[1]), AsmArg(AsmTypes.ACC), rop="/")
        if (nac.op == "mod2"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg.build_arg(nac.args[1]), AsmArg(AsmTypes.ACC), rop="mod")
        # === inst: binary operations # END

        # === inst: jump operations # START
        if (nac.op == "jnez"):  # TODO: jnez imm:i32 # a label str in *.dis file # support imm in future
            return TAC.tac_cond_jmp(
                AsmArg(AsmTypes.LABEL, nac.args[0]),
                AsmArg(AsmTypes.ACC),
                AsmArg(AsmTypes.ZERO),
                "!=")
        if (nac.op == "jeqz"):  # TODO: jeqz imm:i32 # a label str in *.dis file # support imm in future
            return TAC.tac_cond_jmp(
                AsmArg(AsmTypes.LABEL, nac.args[0]),
                AsmArg(AsmTypes.ACC),
                AsmArg(AsmTypes.ZERO),
                "==")
        if (nac.op == "jmp"):
            return TAC.tac_uncn_jmp(AsmArg(AsmTypes.LABEL, nac.args[0]), log="todo: check label's existence")
        # === inst: jump operations # END

        # === inst: call runtime functions # START
        if (nac.op == "callruntime.isfalse"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.FALSE), rop="==")
        if (nac.op == "callruntime.istrue"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.TRUE), rop="==")
        # === inst: call runtime functions # END

        # === inst: call instructions # START
        if (nac.op == "callthis0"):
            return TAC.tac_call(
                arg_len=AsmArg(AsmTypes.IMM, value=0), paras=[], this=AsmArg.build_arg(nac.args[1]))
        if (nac.op == "callthis1"):
            return TAC.tac_call(
                arg_len=AsmArg(AsmTypes.IMM, value=1),
                paras=[AsmArg.build_arg(nac.args[2])],
                this=AsmArg.build_arg(nac.args[1]))
        if (nac.op == "callthis2"):
            return TAC.tac_call(
                arg_len=AsmArg(AsmTypes.IMM, value=2),
                paras=[AsmArg.build_arg(nac.args[2]), AsmArg.build_arg(nac.args[3])],
                this=AsmArg.build_arg(nac.args[1]))
        if (nac.op == "callthis3"):
            return TAC.tac_call(
                arg_len=AsmArg(AsmTypes.IMM, value=3),
                paras=[AsmArg.build_arg(nac.args[2]), AsmArg.build_arg(nac.args[3]), AsmArg.build_arg(nac.args[4])],
                this=AsmArg.build_arg(nac.args[1]))
        if (nac.op == "callarg0"):
            return TAC.tac_call(
                arg_len=AsmArg(AsmTypes.IMM, value=0),
                paras=[])
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

        # === inst: object creaters # START
        if (nac.op == "createemptyobject"):
            return TAC.tac_assign(AsmArg(AsmTypes.ACC), AsmArg(AsmTypes.OBJECT, value=None))
        # === inst: object creaters # END

        # === inst: object visitors # START
        if (nac.op == "ldobjbyname"):
            return TAC.tac_assign(
                AsmArg(AsmTypes.ACC, obj_ref=AsmArg(AsmTypes.ACC)),
                AsmArg(AsmTypes.STR, value=nac.args[1]),
                log=f"arg0: {nac.args[0]} todo: check ldobjbyname")
        if (nac.op == "tryldglobalbyname"):
            return TAC.tac_assign(
                AsmArg(AsmTypes.ACC),
                AsmArg(AsmTypes.STR, value=nac.args[1]),
                log=f"arg0: {nac.args[0]} todo: check tryldglobalbyname, not throw now")
        if (nac.op == "ldexternalmodulevar"):
            index = int(nac.args[0], base=16)
            module_name = dis_file.get_external_module_name(index, asm_method.file_class_name)
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
