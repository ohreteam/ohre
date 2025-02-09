import copy
from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.AsmLiteral import AsmLiteral
from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.CodeBlocks import CodeBlocks
from ohre.abcre.dis.DisFile import DisFile
from ohre.abcre.dis.enum.AsmTypes import AsmTypes
from ohre.abcre.dis.enum.CODE_LV import CODE_LV
from ohre.abcre.dis.enum.NACTYPE import NACTYPE
from ohre.abcre.dis.NAC import NAC
from ohre.abcre.dis.TAC import TAC
from ohre.misc import Log, utils


class NACtoTAC:
    @classmethod
    def toTAC(self, nac: NAC, meth: AsmMethod, dis_file: DisFile) -> Union[TAC, List[TAC]]:
        print(f"nac_: {nac._debug_vstr()}")  # TODO: more tac builder plz
        if (nac.type == NACTYPE.LABEL):
            return TAC.tac_label(AsmArg(AsmTypes.LABEL, nac.op))

        if (nac.op == "mov"):  # Dynamic move register-to-register
            return TAC.tac_assign(AsmArg.build_arg(nac.args[0]), AsmArg.build_arg(nac.args[1]))
        if (nac.op == "lda"):  # Dynamic load accumulator from register
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[0]))
        if (nac.op == "lda.str"):  # Load accumulator from string constant pool
            return TAC.tac_assign(AsmArg.ACC(), AsmArg(AsmTypes.STR, value=utils.strip_sted_str(nac.args[0])))
        if (nac.op == "ldai"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg(AsmTypes.IMM, value=int(nac.args[0], 16)))
        if (nac.op == "fldai"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg(AsmTypes.IMM, value=float(nac.args[0])))
        if (nac.op == "sta"):  # Dynamic store accumulator
            return TAC.tac_assign(AsmArg.build_arg(nac.args[0]), AsmArg.ACC())

        # === inst: constant object loaders # START
        if (nac.op == "ldnan"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg(AsmTypes.NAN))
        if (nac.op == "ldinfinity"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg(AsmTypes.INF))
        if (nac.op == "ldtrue"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg(AsmTypes.TRUE))
        if (nac.op == "ldfalse"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg(AsmTypes.FALSE))
        if (nac.op == "ldhole"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg(AsmTypes.HOLE))
        if (nac.op == "ldnull"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg(AsmTypes.NULL))
        if (nac.op == "ldundefined"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg(AsmTypes.UNDEFINED))
        if (nac.op == "asyncfunctionenter"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg(AsmTypes.METHOD_OBJ, name="__asyncfunctionenter"))
        if (nac.op == 'poplexenv'):
            return TAC.tac_call(arg_len=AsmArg(AsmTypes.IMM, value=1),
                                paras=[AsmArg(AsmTypes.LEXENV, name='__poplexenv', value=[None])])
        # === inst: constant object loaders # END

        # === inst: comparation instructions # START
        if (nac.op == "isin"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop="in")
        if (nac.op == "instanceof"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop="instanceof")
        if (nac.op == "stricteq"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), rop="===")
        if (nac.op == "strictnoteq"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), rop="!==")
        # === inst: comparation instructions # END

        # === inst: unary operations # START
        if (nac.op == "typeof"):
            return TAC.tac_call(arg_len=AsmArg(AsmTypes.IMM, value=1),
                                paras=[AsmArg.ACC()],
                                call_addr=AsmArg(AsmTypes.METHOD, name="__typeof"),)
        if (nac.op == "isfalse"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.ACC(), AsmArg(AsmTypes.FALSE), rop="==")
        if (nac.op == "istrue"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.ACC(), AsmArg(AsmTypes.TRUE), rop="==")
        if (nac.op == "neg"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.ACC(), rop="-")
        if (nac.op == "deprecated.neg"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.ACC(), rop="-")
        if (nac.op == "inc"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.ACC(), AsmArg(AsmTypes.IMM, value=1), rop="+")
        if (nac.op == "deprecated.inc"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.ACC(), AsmArg(AsmTypes.IMM, value=1), rop="+")
        if (nac.op == "dec"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.ACC(), AsmArg(AsmTypes.IMM, value=1), rop="-")
        if (nac.op == "deprecated.dec"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.ACC(), AsmArg(AsmTypes.IMM, value=1), rop="-")
        # === inst: unary operations # END

        # === inst: binary operations # START
        if (nac.op == "eq"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), rop="==")
        if (nac.op == "noteq"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), rop="!=")
        if (nac.op == "less"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop="<")
        if (nac.op == "lesseq"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop="<=")
        if (nac.op == "greater"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop=">")
        if (nac.op == "greatereq"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop=">=")
        if (nac.op == "shl2"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop="<<")
        if (nac.op == "shr2"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop=">>>")
        if (nac.op == "ashr2"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop=">>")
        if (nac.op == "and2"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop="&")
        if (nac.op == "or2"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop="|")
        if (nac.op == "xor2"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop="^")
        if (nac.op == "exp"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop="**")
        if (nac.op == "add2"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop="+")
        if (nac.op == "sub2"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop="-")
        if (nac.op == "mul2"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop="*")
        if (nac.op == "div2"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop="/")
        if (nac.op == "mod2"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arg(nac.args[1]), AsmArg.ACC(), rop="mod")
        # === inst: binary operations # END

        # === throw instructions # START
        if (nac.op == "throw"):
            return TAC.tac_uncn_throw(exception=AsmArg.ACC())
        if (nac.op == "throw.undefinedifholewithname"):
            return TAC.tac_cond_throw(
                para0=AsmArg.ACC(), para1=AsmArg(AsmTypes.HOLE), rop="==",
                exception=AsmArg(AsmTypes.STR, value=utils.strip_sted_str(nac.args[0])))
        if (nac.op == "throw.ifsupernotcorrectcall"):
            error_type = int(nac.args[0], 16)
            tmp_var = AsmArg.build_arg("tmp0")
            inst0 = TAC.tac_call(
                arg_len=AsmArg(AsmTypes.IMM, value=1), paras=[AsmArg.ACC()], ret_store_to=tmp_var,
                call_addr=AsmArg(AsmTypes.METHOD, name="__is_super_called_correctly"))
            inst1 = TAC.tac_cond_throw(
                para0=tmp_var,
                para1=AsmArg(AsmTypes.FALSE),
                rop="==", exception=AsmArg(AsmTypes.IMM, value=error_type))
            return [inst0, inst1]
        # === throw instructions # END

        # === inst: jump operations # START
        if (nac.op == "jnez"):  # NOTE: jnez imm:i32 # a label str in *.dis file # support imm in future
            return TAC.tac_cond_jmp(
                AsmArg(AsmTypes.LABEL, nac.args[0]),
                AsmArg.ACC(),
                AsmArg(AsmTypes.ZERO),
                "!=")
        if (nac.op == "jeqz"):  # NOTE: jeqz imm:i32 # a label str in *.dis file # support imm in future
            return TAC.tac_cond_jmp(
                AsmArg(AsmTypes.LABEL, nac.args[0]),
                AsmArg.ACC(),
                AsmArg(AsmTypes.ZERO),
                "==")
        if (nac.op == "jmp"):
            return TAC.tac_uncn_jmp(AsmArg(AsmTypes.LABEL, nac.args[0]))
        # === inst: jump operations # END

        # === inst: call runtime functions # START
        if (nac.op == "callruntime.isfalse"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.ACC(), AsmArg(AsmTypes.FALSE), rop="==")
        if (nac.op == "callruntime.istrue"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.ACC(), AsmArg(AsmTypes.TRUE), rop="==")
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
            return TAC.tac_call(arg_len=AsmArg(AsmTypes.IMM, value=0), paras=[])
        if (nac.op == "callarg1"):
            return TAC.tac_call(arg_len=AsmArg(AsmTypes.IMM, value=1), paras=[AsmArg.build_arg(nac.args[1])])
        if (nac.op == "callargs2"):
            return TAC.tac_call(arg_len=AsmArg(AsmTypes.IMM, value=2),
                                paras=[AsmArg.build_arg(nac.args[1]), AsmArg.build_arg(nac.args[2])])
        if (nac.op == "callargs3"):
            return TAC.tac_call(
                arg_len=AsmArg(AsmTypes.IMM, value=3),
                paras=[AsmArg.build_arg(nac.args[1]), AsmArg.build_arg(nac.args[2]), AsmArg.build_arg(nac.args[3])])
        if (nac.op == "callthisrange"):
            # callthisrange reserved, para_cnt, this_ptr # acc: method obj # para(cnt): this_ptr para0 ...
            arg_len = int(nac.args[1], 16)
            paras_l = list()
            this_p = AsmArg.build_arg(nac.args[2])
            arg = this_p
            for i in range(arg_len):
                arg = arg.build_next_arg()
                paras_l.append(arg)
            return TAC.tac_call(arg_len=AsmArg(AsmTypes.IMM, value=arg_len), paras=paras_l, this=this_p)
        if (nac.op == "supercallspread"):
            args_arr = AsmArg.build_arg(nac.args[1])
            return TAC.tac_call(arg_len=AsmArg(AsmTypes.IMM, value=0), paras=[args_arr],
                                this=AsmArg.ACC(), call_addr=AsmArg(AsmTypes.METHOD, name="__super"))
        if (nac.op == "supercallthisrange"):
            arg_len = int(nac.args[1], 16)
            paras = list()
            if (arg_len == 0):
                paras.append(AsmArg(AsmTypes.UNDEFINED))
            else:
                arg = AsmArg.build_arg(nac.args[2])
                for i in range(arg_len):
                    paras.append(arg)
                    arg = arg.build_next_arg()
            inst_call = TAC.tac_call(arg_len=AsmArg(AsmTypes.IMM, value=arg_len), paras=paras,
                                     call_addr=AsmArg(AsmTypes.METHOD, name="__super"), ret_store_to=AsmArg.NULL())
            inst_ret = TAC.tac_assign(AsmArg.ACC(), AsmArg.build_this(), log="TODO: __super return ptr this?")
            return [inst_call, inst_ret]
        if (nac.op == "wide.supercallthisrange"):
            arg_len = int(nac.args[0], 16)
            paras = list()
            if (arg_len == 0):
                paras.append(AsmArg(AsmTypes.UNDEFINED))
            else:
                arg = AsmArg.build_arg(nac.args[1])
                for i in range(arg_len):
                    paras.append(arg)
                    arg = arg.build_next_arg()
            return TAC.tac_call(arg_len=AsmArg(AsmTypes.IMM, value=arg_len), paras=paras,
                                call_addr=AsmArg(AsmTypes.METHOD, name="__super"))
        # === inst: call instructions # END

        # === inst: dynamic return # START
        if (nac.op == "returnundefined"):
            return TAC.tac_return(AsmArg(AsmTypes.UNDEFINED))
        if (nac.op == "return"):
            return TAC.tac_return(AsmArg.ACC())
        # === inst: dynamic return # END

        # === inst: object creaters # START
        if (nac.op == "createemptyobject"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_object(None))
        if (nac.op == "newobjrange"):
            arg_len = int(nac.args[1], 16)
            call_addr = AsmArg.build_arg(nac.args[2])
            arg = call_addr
            paras = list()
            for i in range(arg_len - 1):
                arg = arg.build_next_arg()
                paras.append(arg)
            return TAC.tac_call(AsmArg(AsmTypes.IMM, value=int(nac.args[1], 16)), paras, call_addr=call_addr)
        if (nac.op == "createobjectwithbuffer"):
            kv_dict = AsmLiteral.literal_get_key_value("{" + nac.args[1] + "}")
            arg_obj = AsmArg.build_object(kv_dict)
            return TAC.tac_assign(AsmArg.ACC(), arg_obj)
        if (nac.op == "newlexenv"):
            slots = int(nac.args[0], base=16)
            return TAC.tac_call(arg_len=AsmArg(AsmTypes.IMM, value=1),
                                paras=[AsmArg(AsmTypes.LEXENV, name="__newlexenv", value=[slots])])
        if (nac.op == "newlexenvwithname"):
            slots = int(nac.args[0], base=16)
            literal_id = nac.args[1]
            return TAC.tac_call(arg_len=AsmArg(AsmTypes.IMM, value=1),
                                paras=[AsmArg(AsmTypes.LEXENV, name="__newlexenvwithname", value=[slots, literal_id])])
        # === inst: object creaters # END

        # === inst: object visitors # START
        if (nac.op == "ldobjbyname"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_object(
                None, name=utils.strip_sted_str(nac.args[1]), ref_base=AsmArg.ACC()))
        if (nac.op == "tryldglobalbyname"):
            return TAC.tac_assign(
                AsmArg.ACC(), AsmArg.build_object(None, name=utils.strip_sted_str(nac.args[1])),
                log=f"todo: ld global var, not throw now")
        if (nac.op == "trystglobalbyname"):
            return TAC.tac_assign(
                AsmArg.build_object(None, name=utils.strip_sted_str(nac.args[1])), AsmArg.ACC(),
                log=f"todo: st global var, not throw now")
        if (nac.op == "ldexternalmodulevar"):
            index = int(nac.args[0], base=16)
            module_name = dis_file.get_external_module_name(index, meth.file_class_name)
            if (module_name is not None and len(module_name) > 0):
                return TAC.tac_import(AsmArg(AsmTypes.MODULE, name=module_name))
            else:
                Log.error(f"module load failed, nac: {nac}")
        if (nac.op == "copyrestargs"):
            return TAC.tac_assign(AsmArg.ACC(), AsmArg.build_arr(meth.get_args(), "arr_copyrestargs"))
        if (nac.op == "stownbyname" or nac.op == "stobjbyname"):  # arg2[arg1] = acc
            dest = AsmArg(AsmTypes.FIELD, name=utils.strip_sted_str(nac.args[1]),
                          ref_base=AsmArg.build_arg(utils.strip_sted_str(nac.args[2])))
            return TAC.tac_assign(dest, AsmArg.ACC())
        if (nac.op == "stmodulevar"):  # TODO: global var related
            return TAC.tac_call(AsmArg(AsmTypes.IMM, value=2),
                                [AsmArg(AsmTypes.IMM, value=int(nac.args[0], 16)), AsmArg.ACC()],
                                call_addr=AsmArg(AsmTypes.METHOD, name="__stmodulevar"),
                                ret_store_to=AsmArg.NULL())
        if (nac.op == "asyncfunctionresolve"):
            return TAC.tac_call(AsmArg(AsmTypes.IMM, value=2), [AsmArg.build_arg(nac.args[0]), AsmArg.ACC()],
                                call_addr=AsmArg(AsmTypes.METHOD, name="__asyncfunctionresolve"))
        if (nac.op == "asyncfunctionreject"):
            return TAC.tac_call(AsmArg(AsmTypes.IMM, value=2), [AsmArg.build_arg(nac.args[0]), AsmArg.ACC()],
                                call_addr=AsmArg(AsmTypes.METHOD, name="__asyncfunctionreject"))
        if (nac.op == "stlexvar"):
            lexenv_layer = int(nac.args[0], base=16)
            slot_index = int(nac.args[1], base=16)
            dest = AsmArg(AsmTypes.LEXENV, value=[lexenv_layer, slot_index])
            return TAC.tac_call(arg_len=AsmArg(AsmTypes.IMM, value=1),
                                paras=[dest])
        if (nac.op == 'ldlexvar'):
            lexenv_layer = int(nac.args[0], base=16)
            slot_index = int(nac.args[1], base=16)
            return TAC.tac_call(arg_len=AsmArg(AsmTypes.IMM, value=1),
                                paras=[AsmArg(AsmTypes.LEXENV, name="__ldlexvar",
                                              value=[lexenv_layer, slot_index])])
        # === inst: object visitors # END

        # === inst: definition instuctions # START
        if (nac.op == "definegettersetterbyvalue"):
            # definegettersetterbyvalue v1: object, v2: key of v1, v3: getter METHOD_OBJ, v4: setter METHOD_OBJ
            # acc-in: bool, Whether to set a name for the accessor # acc-out:
            return TAC.tac_call(AsmArg(AsmTypes.IMM, value=5),
                                [AsmArg.ACC(), AsmArg.build_arg(nac.args[0]), AsmArg.build_arg(nac.args[1]),
                                 AsmArg.build_arg(nac.args[2]), AsmArg.build_arg(nac.args[3])],
                                call_addr=AsmArg(AsmTypes.METHOD, name="__definegettersetterbyvalue"))
        if (nac.op == "definefunc"):
            return TAC.tac_assign(
                AsmArg.ACC(),
                AsmArg(AsmTypes.METHOD_OBJ, value=nac.args[1], paras_len=int(nac.args[2], 16)))
        if (nac.op == "definemethod"):
            paras_len = int(nac.args[2], 16)
            method_obj = AsmArg(AsmTypes.METHOD_OBJ, value=nac.args[1], paras_len=paras_len)
            inst0 = TAC.tac_assign(AsmArg(AsmTypes.FIELD, name="HomeObject", ref_base=method_obj), AsmArg.ACC())
            inst1 = TAC.tac_assign(AsmArg.ACC(),
                                   AsmArg(AsmTypes.METHOD_OBJ, value=nac.args[1], paras_len=paras_len))
            return [inst0, inst1]
        if (nac.op == "defineclasswithbuffer"):
            constructor_str = AsmArg(AsmTypes.STR, value=nac.args[1])
            class_lit = AsmArg(AsmTypes.STR, value=nac.args[2])
            class_para_len = AsmArg(AsmTypes.IMM, value=int(nac.args[3], 16))
            parent_class = AsmArg.build_arg(nac.args[4])
            return TAC.tac_call(
                AsmArg(AsmTypes.IMM, value=4),
                [constructor_str, class_lit, class_para_len, parent_class],
                call_addr=AsmArg(AsmTypes.METHOD, name="__defineclasswithbuffer"))
        # === inst: definition instuctions # END

        # === inst: iterator instructions # START
        if (nac.op == "definepropertybyname"):
            dest = AsmArg(AsmTypes.FIELD, name=utils.strip_sted_str(nac.args[1]),
                          ref_base=AsmArg.build_arg(utils.strip_sted_str(nac.args[2])))
            return TAC.tac_assign(dest, AsmArg.ACC())
        # === inst: iterator instructions # END

        if (nac.op == "nop"):
            return None

        Log.warn(f"toTAC failed, not support nac inst: {nac._debug_vstr()}", False)  # to error when done
        return TAC.tac_unknown(
            [AsmArg(AsmTypes.UNKNOWN, nac.args[i]) for i in range(len(nac.args))],
            log=f"todo: {nac.op} {[nac.args[i] for i in range(len(nac.args))]}")

    @classmethod
    def trans_NAC_to_TAC(cls, meth: AsmMethod, dis_file: DisFile) -> bool:
        cbs = meth.code_blocks
        if (cbs.level != CODE_LV.NATIVE_BLOCK_SPLITED):
            Log.error(f"cbs level is NOT NATIVE_BLOCK_SPLITED")
            return False
        for i in range(len(cbs.blocks)):
            tac_inst_l = list()
            for nac_inst in cbs.blocks[i].insts:
                tac_s = NACtoTAC.toTAC(nac_inst, meth, dis_file)
                if (tac_s is None):
                    continue
                elif (isinstance(tac_s, TAC)):
                    print(f"tac^: {tac_s._debug_vstr()}")
                    tac_inst_l.append(tac_s)
                else:
                    for tac in tac_s:
                        print(f"tac^: {tac._debug_vstr()}")
                        tac_inst_l.append(tac)
            cbs.blocks[i].insts = tac_inst_l
        return True
