import copy
from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.enum.TACTYPE import TACTYPE
from ohre.abcre.dis.TAC import TAC, in_and_not_None
from ohre.misc import Log, utils


def CopyPropagation(meth: AsmMethod):
    print(f"\n\n>>> CPro-START {meth.name} {meth._debug_vstr()}")
    for cb in meth.code_blocks:
        cb.empty_var2val()
    i = 0
    for cb in meth.code_blocks:
        var2val = CPro_cb(cb)
        cb.set_var2val(var2val)
        CPro_cb(cb, DEBUG_MSG=f"CPro_{i}_{len(meth.code_blocks)}")  # now var2val in cb updated, CPro it again
        i += 1
    print(f">>> CPro-END {meth.name} {meth._debug_vstr()}")


def CPro_cb(cb: CodeBlock, DEBUG_MSG: str = "") -> Dict[AsmArg, AsmArg]:
    print(f"\n\n ===================================== {DEBUG_MSG}")
    var2val: Dict[AsmArg, AsmArg] = cb.get_all_prev_cbs_var2val(get_current_cb=False, definite_flag=True)
    print(f"\n >>>> CPro_cb START {DEBUG_MSG} cb: {cb._debug_vstr()} var2val {var2val}")
    for i in range(cb.get_insts_len()):
        inst = cb.insts[i]
        print(f"CPro_cb inst START inst {inst} {inst._debug_vstr()} var2val {var2val}")
        inst.copy_propagation(var2val)
        if (not inst.is_arg0_def()):  # NOTE: skip a inst that not assign any arg (if assigned, must be arg0)
            continue
        if ((inst.is_simple_assgin() and inst.args[0].is_no_ref()) or inst.type == TACTYPE.IMPORT):
            var2val[inst.args[0]] = inst.args[1]
        elif (inst.args[0].has_ref() and inst.args[0].is_field()
                and in_and_not_None(inst.args[0].ref_base, var2val)
                and var2val[inst.args[0].ref_base].obj_has_key(inst.args[0])):
            print(f"before {var2val[inst.args[0].ref_base]}")
            ret = var2val[inst.args[0].ref_base].set_object_key_value(inst.args[0].name, inst.args[1])
            print(f"after  {var2val[inst.args[0].ref_base]} {ret}")
        elif (inst.args_len == 2 and inst.rop == "-" and inst.args[1].is_imm()):  # a = - imm(xxx)
            if (inst.args[1].is_imm()):
                inst.rop = ""
                inst.args[1].value = - inst.args[1].value
                var2val[inst.args[0]] = inst.args[1]
            elif (in_and_not_None(inst.args[1], var2val) and var2val[inst.args[1]].is_imm()):  # a = - b
                inst.args[1] = copy.deepcopy(var2val[inst.args[1]])
                inst.args[1].value = - var2val[inst.args[1]].value
                var2val[inst.args[0]] = inst.args[1]
            else:
                var2val[inst.args[0]] = None
                Log.error(f"ERROR-CPro_cb! a = - b else hit, inst {inst}")
        elif (inst.type == TACTYPE.CALL):
            if (inst.args[0] in var2val):
                var2val[inst.args[0]] = None
        else:  # TODO: if hit here, something need to be check, and support it!
            if (inst.args[0] in var2val):
                var2val[inst.args[0]] = None
            Log.error(f"ERROR-CPro_cb! else hit, inst {inst} is_arg0_def {inst.is_arg0_def()} var2val {var2val}")
        print(f"CPro_cb inst END inst {inst} {inst._debug_vstr()} var2val {var2val}")
    print(f"\n >>>> CPro_cb END {DEBUG_MSG} // var2val {var2val}")
    return var2val
