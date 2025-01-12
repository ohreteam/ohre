import copy
from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.enum.TACTYPE import TACTYPE
from ohre.abcre.dis.lifting.LivingVar import _update_method_current_cb_use_vars
from ohre.abcre.dis.TAC import TAC


def PeepholeOptimization(meth: AsmMethod):
    print(f"PHO-START {meth.name} {meth.level_str}")
    for cb in meth.code_blocks:
        PHO_cb(cb)
        PHO_cb_reverse(cb)  # e.g. a=xxx; b=a; a not used later
        print(f"PHO_cb-END PHO_cb_reverse-END {cb._debug_vstr()}")
    print(f"PHO-END {meth.name} {meth.level_str}")


def PHO_cb(cb: CodeBlock):
    # PHO is short for PeepHole Optimization
    idx_old2new: Dict[int, int] = dict()  # pending replaced inst idx
    new_idx2inst: Dict[int, TAC] = dict()
    for i in range(cb.get_insts_len() - 1):
        if (i in idx_old2new.keys() or i + 1 in idx_old2new.keys()):
            continue
        curr_inst, next_inst = cb.insts[i], cb.insts[i + 1]
        curr_def, curr_use = curr_inst.get_def_use()
        curr_def, curr_use = list(curr_def), list(curr_use)
        next_def, next_use = next_inst.get_def_use()
        next_def, next_use = list(next_def), list(next_use)

        NOT_change = True
        # PH-1: a=b; b=a;  =>  a=b;
        if (NOT_change and curr_inst.type == TACTYPE.ASSIGN and next_inst.type == TACTYPE.ASSIGN
                and len(curr_inst.args) == 2 and len(next_inst.args) == 2
                and curr_inst.args[0] == next_inst.args[1] and curr_inst.args[1] == next_inst.args[0]):
            new_idx2inst[i] = curr_inst
            idx_old2new[i], idx_old2new[i + 1] = i, i
            NOT_change = False
        # PH-2: a=xxx; b=a; a=yyy (yyy not used a)  =>  b=xxx; a=yyy; xxx may be a call or some other
        if (NOT_change and i + 2 < cb.get_insts_len()
                and next_inst.type == TACTYPE.ASSIGN and len(next_inst.args) == 2
                and curr_inst.args[0] == next_inst.args[1] and curr_inst.args[0] == cb.insts[i + 2].args[0]):
            mid_var_def_later = (cb.insts[i + 2].is_def(curr_inst.args[0])
                                 and (not cb.insts[i + 2].is_use(curr_inst.args[0])))
            print(f"mid_var_def_later {mid_var_def_later} {curr_inst}; {next_inst}; {cb.insts[i + 2]};")
            if (mid_var_def_later):
                curr_inst.replace_def_var(next_inst.args[0])
                new_idx2inst[i] = curr_inst

                # TAC.tac_assign(next_inst.args[0], curr_inst.args[1], log=curr_inst.log + next_inst.log)
                idx_old2new[i], idx_old2new[i + 1] = i, i
                NOT_change = False
        # a=xxx (assign tac, def) ; a=yyy (def not used) # delete a=xxx
        if (NOT_change and curr_inst.type == TACTYPE.ASSIGN and len(curr_def) == 1 and len(next_def) == 1
                and curr_def == next_def and curr_def[0] not in next_use):
            new_idx2inst[i] = next_inst
            idx_old2new[i], idx_old2new[i + 1] = i, i
            NOT_change = False
            print(f"d3bug hit {curr_inst} {next_inst} \t curr/next def {curr_def} {next_def} use {curr_use} {next_use}")

    update_cb_insts(cb, idx_old2new, new_idx2inst)


def PHO_cb_reverse(cb: CodeBlock):
    idx_old2new: Dict[int, int] = dict()  # pending replaced inst idx
    new_idx2inst: Dict[int, TAC] = dict()

    used_after: set = cb.get_all_next_cbs_use_vars()
    for i in range(cb.get_insts_len() - 1, 0, -1):
        if (i not in idx_old2new.keys() and i - 1 not in idx_old2new.keys()):
            NOT_change = True
            pre1_inst, curr_inst = cb.insts[i - 1], cb.insts[i]
            pre1_def, pre1_use = pre1_inst.get_def_use_list()
            curr_def, curr_use = curr_inst.get_def_use_list()
            # PHO-reverse: pre1: a=xxx; curr: b=a; a not used later
            if (NOT_change and curr_inst.type == TACTYPE.ASSIGN
                    and len(curr_def) == 1 and len(curr_use) == 1 and len(pre1_def) == 1
                    and pre1_def[0] == curr_use[0] and curr_use[0] not in used_after):
                new_inst = copy.deepcopy(pre1_inst)
                new_inst.replace_def_var(curr_def[0])
                idx_old2new[i], idx_old2new[i - 1] = i, i
                new_idx2inst[i] = new_inst
                NOT_change = False

        def_vars_inst, use_vars_inst = cb.insts[i].get_def_use()  # must update at last
        used_after.update(use_vars_inst)

    update_cb_insts(cb, idx_old2new, new_idx2inst)


def update_cb_insts(cb: CodeBlock, idx_old2new: Dict[int, int], new_idx2inst: Dict[int, TAC]):
    tac_l: List[TAC] = list()
    for i in range(cb.get_insts_len()):
        if (i in idx_old2new.keys() and idx_old2new[i] in new_idx2inst.keys()):
            tac_l.append(new_idx2inst[idx_old2new[i]])
            print(f"inst_replace {i} {cb.insts[i]} to {new_idx2inst[idx_old2new[i]]}")
            new_idx2inst.pop(idx_old2new[i], None)
        elif (i in idx_old2new.keys()):
            continue  # this old inst point to a new inst idx that already append
        else:
            tac_l.append(cb.insts[i])  # no op, just store it
    cb.replace_insts(tac_l)
