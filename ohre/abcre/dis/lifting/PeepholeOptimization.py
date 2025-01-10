from typing import Any, Dict, Iterable, List, Tuple, Union
from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.lifting.LivingVar import _update_method_current_cb_use_vars
from ohre.abcre.dis.enum.TACTYPE import TACTYPE

from ohre.abcre.dis.TAC import TAC


def PeepholeOptimization(meth: AsmMethod):
    print(f"PHO-START {meth.name} {meth.level_str}")
    for cb in meth.code_blocks:
        print(f"PHO_cb-START {cb._debug_vstr()}")
        PHO_cb(cb)
        print(f"PHO_cb-END   {cb._debug_vstr()}")
    print(f"PHO-END {meth.name} {meth.level_str}")


def PHO_cb(cb: CodeBlock):
    # PHO is short for PeepHole Optimization
    old_idx2new_idx: Dict[int, int] = dict()
    new_inst_idx2inst: Dict[int, TAC] = dict()
    for i in range(cb.get_insts_len() - 1):
        curr_inst = cb.insts[i]
        next_inst = cb.insts[i + 1]
        if (i not in old_idx2new_idx.keys() and i + 1 not in old_idx2new_idx.keys()):
            if (curr_inst.type == TACTYPE.ASSIGN and next_inst.type == TACTYPE.ASSIGN
               and len(curr_inst.args) == 2 and len(next_inst.args) == 2):
                # PH-1: a=b; b=a;  =>  a=b;
                if (curr_inst.args[0] == next_inst.args[1]
                        and curr_inst.args[1] == next_inst.args[0]):
                    print(f"curr_inst {curr_inst} next_inst {next_inst}")
                    new_inst_idx2inst[i] = curr_inst
                    old_idx2new_idx[i], old_idx2new_idx[i + 1] = i, i
                # PH-2: a=b; c=a; a=xxx  =>  c=b;
                elif (i + 2 < cb.get_insts_len()
                      and curr_inst.args[0] == next_inst.args[1]
                      and next_inst.args[1] == cb.insts[i + 2].args[0]):
                    mid_var_def_later = (cb.insts[i + 2].is_def(curr_inst.args[0])
                                         and (not cb.insts[i + 2].is_use(curr_inst.args[0])))
                    print(f"mid_var_def_later {mid_var_def_later} \
{cb.insts[i + 2].is_def(curr_inst.args[0])}{not cb.insts[i + 2].is_use(curr_inst.args[0])} \
curr_inst {curr_inst} {next_inst} {next_inst}")
                    if (mid_var_def_later):
                        new_inst_idx2inst[i] = TAC.tac_assign(
                            next_inst.args[0],
                            curr_inst.args[1],
                            log=curr_inst.log + next_inst.log)
                        old_idx2new_idx[i], old_idx2new_idx[i + 1] = i, i

    print(f"old_idx2new_idx {old_idx2new_idx}")
    print(f"new_inst_idx2inst {new_inst_idx2inst}")
    tac_l: List[TAC] = list()
    for i in range(cb.get_insts_len()):
        if (i in old_idx2new_idx.keys() and old_idx2new_idx[i] in new_inst_idx2inst.keys()):
            tac_l.append(new_inst_idx2inst[old_idx2new_idx[i]])
            print(f"replace {i} {cb.insts[i]} to {new_inst_idx2inst[old_idx2new_idx[i]]}")
            new_inst_idx2inst.pop(old_idx2new_idx[i], None)
        elif (i in old_idx2new_idx.keys()):
            continue  # this old inst point to a new inst idx that already append
        else:
            tac_l.append(cb.insts[i])  # no op, just store it
    cb.replace_insts(tac_l)
