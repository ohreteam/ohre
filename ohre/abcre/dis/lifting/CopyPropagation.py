import copy
from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.enum.TACTYPE import TACTYPE
from ohre.abcre.dis.TAC import TAC, in_and_not_None
from ohre.misc import Log, utils


def CopyPropagation(meth: AsmMethod):
    Log.info(f"CPro-START {meth.module_method_name} inst-{meth.inst_len}", True)
    for cb in meth.code_blocks:
        cb.empty_var2val()
    i = 0
    for cb in meth.code_blocks:
        var2val = CPro_cb(cb, DEBUG_MSG=f"CPro_{i}_{len(meth.code_blocks)} Round0")
        cb.set_var2val(var2val)
        # now var2val in cb updated, CPro it again
        CPro_cb(cb, DEBUG_MSG=f"CPro_{i}_{len(meth.code_blocks)} Round1")
        i += 1
    # print(f">>> CPro-END {meth.name} {meth._debug_vstr()}")


def is_refbase_same_recursive(var, value) -> bool:  # x = x->y; x = x->a->b # return True
    if (isinstance(var, AsmArg) and isinstance(value, AsmArg)):
        if (value.has_ref() and value.ref_base == var):
            return True
        if (value.has_ref()):
            return is_refbase_same_recursive(var, value.ref_base)
    return False


def var2val_assign(var2val: Dict, var, val):
    if (is_refbase_same_recursive(var, val)):
        Log.info(f"var2val_assign: var {var} : val {val}, set var2val[var] to None")
        var2val[var] = None
    else:
        var2val[var] = val


def CPro_cb(cb: CodeBlock, DEBUG_MSG: str = "") -> Dict[AsmArg, AsmArg]:
    var2val: Dict[AsmArg, AsmArg] = cb.get_all_prev_cbs_var2val(get_current_cb=False, definite_flag=True)
    Log.info(f"CPro-START-cb {DEBUG_MSG} cb: {cb._debug_str()} var2val {len(var2val)}")
    for i in range(cb.get_insts_len()):
        inst = cb.insts[i]
        # print(f"CPro_cb inst START {i}/{cb.get_insts_len()} {inst} {inst._debug_vstr()} var2val {var2val}")
        inst.copy_propagation(var2val)
        if (not inst.is_arg0_def()):  # NOTE: skip a inst that not assign any arg (if assigned, must be arg0)
            continue
        if ((inst.is_simplest_assgin() and inst.args[0].is_no_ref()) or inst.type == TACTYPE.IMPORT):
            var2val_assign(var2val, inst.args[0], inst.args[1])
        elif (inst.args[0].has_ref() and (inst.args[0].is_field() or inst.args[0].is_obj())
                and in_and_not_None(inst.args[0].ref_base, var2val)
                and var2val[inst.args[0].ref_base].obj_has_key(inst.args[0])):
            # v1[x] = y , x is a field of v1
            print(f"before {var2val[inst.args[0].ref_base]} inst: {inst}")
            ret = var2val[inst.args[0].ref_base].set_object_key_value(inst.args[0].name, inst.args[1])
            if (ret == False):
                Log.error(f"set_object_key_value False {DEBUG_MSG}, name {inst.args[0].name} value {inst.args[1]}")
            print(f"after  {var2val[inst.args[0].ref_base]} {ret} inst: {inst}")
        elif (inst.args_len == 2 and inst.rop == "-" and inst.args[1].is_imm()):  # a = - imm(xxx)
            if (inst.args[1].is_imm()):
                inst.rop = ""
                inst.args[1].value = - inst.args[1].value
                var2val_assign(var2val, inst.args[0], inst.args[1])
            elif (in_and_not_None(inst.args[1], var2val) and var2val[inst.args[1]].is_imm()):  # a = - b
                inst.args[1] = copy.deepcopy(var2val[inst.args[1]])
                inst.args[1].value = - var2val[inst.args[1]].value
                var2val_assign(var2val, inst.args[0], inst.args[1])
            else:
                var2val_assign(var2val, inst.args[0], None)
                Log.error(f"ERROR-CPro_cb! a = - b else hit, inst {inst}")
        elif (inst.is_simplest_assgin() and inst.args[0].has_ref() and isinstance(inst.args[0].ref_base, AsmArg)
              and inst.args[0].ref_base.is_arg_this()):
            if (inst.args[1].is_specific_like()):
                # this[xx] = True (specific like)
                var2val_assign(var2val, inst.args[0], inst.args[1])
            else:
                # this[xx] = v0
                var2val_assign(var2val, inst.args[0], inst.args[1])
        elif (inst.type == TACTYPE.CALL):
            if (inst.args[0] in var2val):
                var2val_assign(var2val, inst.args[0], None)
        else:  # TODO: if hit here, something need to be check, and support it!
            if (inst.args[0] in var2val):
                var2val_assign(var2val, inst.args[0], None)
            Log.warn(f"ERROR-CPro_cb! else hit, inst {inst} is_arg0_def {inst.is_arg0_def()}", False)
        # print(f"CPro_cb inst END {i}/{cb.get_insts_len()} {inst} {inst._debug_vstr()} var2val {var2val}")
    # print(f"\n >>>> CPro_cb END {DEBUG_MSG} // var2val {var2val}")
    return var2val
