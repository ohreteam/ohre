from typing import Any, Dict, Iterable, List, Tuple, Union

from ohre.abcre.dis.AsmArg import AsmArg
from ohre.abcre.dis.AsmMethod import AsmMethod
from ohre.abcre.dis.CodeBlock import CodeBlock
from ohre.abcre.dis.enum.TACTYPE import TACTYPE
from ohre.abcre.dis.lifting.LivingVar import _update_cbs_def_use_vars_reverse
from ohre.abcre.dis.TAC import TAC
from ohre.misc import Log, utils


def DeadCodeBlockElimination(meth: AsmMethod):
    pass


def DeadCodeElimination(meth: AsmMethod):
    # eliminate the var def but not used inside that code block and the following cbs
    # 1-Delete Dead Code: 1. def in cb 2. NOT used in cb and all next cbs
    # 2-Delete Dead Code:  delete code def in the front but not used and then redef later
    # 3-Delete Dead COde: duplicate insts, like [a=a] [throw s; throw s] [v0=v0+""]
    Log.info(f"DCE-START {meth.file_class_method_name} inst-{meth.inst_len}", True)
    _update_cbs_def_use_vars_reverse(meth)
    i = 0
    for cb in reversed(meth.code_blocks.blocks):
        DCE_cb_reverse(cb, DEBUG_MSG=f"DCE_{i}_{len(meth.code_blocks)}")
        i += 1
    # print(f"DCE-END {meth.name} {meth.level_str}\n\n")


def DCE_cb_reverse(cb: CodeBlock, DEBUG_MSG: str = ""):  # DCE is short for DeadCodeElimination
    # NOTE: reverse order traversal: update vars used into `used_after`
    # if a inst def a var NOT used at `used_after`, mark it as pending delete index set
    used_after: set[AsmArg] = cb.get_all_next_cbs_use_vars(get_current_cb=False)
    # print(f"DCE_cb_reverse START {DEBUG_MSG} cb: {cb} used_after {used_after}")

    # Step-1: add inst that [def a var not in current `used_after`] into pending set (in reverse order)
    pending_delete_inst_idxs: set = set()
    for i in range(cb.inst_len - 1, -1, -1):
        def_vars_inst, use_vars_inst = cb.insts[i].get_def_use_list()
        used_after.update(use_vars_inst)
        used_after_flag = False  # var def in this inst is used after this inst or not
        for var in def_vars_inst:
            if (var in used_after):  # if one var in def_vars_inst used, then this inst cannot be deleted
                used_after_flag = True
                break
        if (used_after_flag == False):  # all def-ed var in this inst are not used after
            pending_delete_inst_idxs.add(i)
        if (len(def_vars_inst) == 1 and def_vars_inst[0] not in use_vars_inst and def_vars_inst[0].is_acc()):
            # TODO: more test needed, more situation needed # NOTE: must be placed in the last
            # if a var def in this inst, but: 1. not used in this inst; 2. is ACC # e.g. acc = v0 + v1 # acc not used
            used_after.discard(def_vars_inst[0])
    cb.set_use_vars(used_after)

    # Step-2: determine: if idxs in pending delete inst idxs actually need to be deleted
    tac_l: List[TAC] = list()
    for i, inst in enumerate(cb.insts):
        if (i in pending_delete_inst_idxs and (inst.type == TACTYPE.ASSIGN or inst.type == TACTYPE.IMPORT)
                and inst.is_arg0_def() and inst.args[0].is_temp_var_like()):
            continue  # delete
        # NOTE: below are duplicate insts that need to be deleted
        # same inst[i] and inst[i+1]
        elif (i + 1 < cb.inst_len and inst == cb.insts[i + 1] and
                (inst.type == TACTYPE.COND_THR or inst.type == TACTYPE.UNCN_THR or inst.type == TACTYPE.IMPORT)):
            continue  # delete
        # v0 = v0
        elif (inst.is_simplest_assgin() and inst.args[0] == inst.args[1]):
            continue  # delete
        # v0 = v0 + "" or v0 = "" + v0
        elif (inst.rop == "+" and inst.type == TACTYPE.ASSIGN and len(inst.args) == 3
              and ((inst.args[0] == inst.args[1] and inst.args[2].is_str_and_eq(""))
                   or (inst.args[0] == inst.args[2] and inst.args[1].is_str_and_eq("")))):
            print(f"TODO: d3bug hit: v0 = v0 + \"\", inst: {cb.insts[i]}")
            continue  # delete
        else:
            tac_l.append(inst)  # NOT delete
    cb.replace_insts(tac_l)
