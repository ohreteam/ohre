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


def DeadCodeElimination(meth: AsmMethod, DEBUG=False):
    # eliminate the var def but not used inside that code block and the following cbs
    # 1-Delete Dead Code: 1. def in cb 2. NOT used in cb and all next cbs
    # 2-Delete Dead Code:  delete code def in the front but not used and then redef later
    # 3-Delete Dead COde: duplicate insts, like [a=a] [throw s; throw s] [v0=v0+""]
    Log.info(f"DCE-START {meth.module_method_name} inst-{meth.inst_len}")
    _update_cbs_def_use_vars_reverse(meth)
    i = 0
    for cb in reversed(meth.code_blocks.blocks):
        DCE_cb_reverse(cb, DEBUG_MSG=f"DCE_{i}_{len(meth.code_blocks)}")
        i += 1
    if(DEBUG):
        print(f"DCE-END {meth.module_method_name} {meth.level_str} {meth._debug_vstr()}\n")


def DCE_cb_reverse(cb: CodeBlock, DEBUG_MSG: str = ""):  # DCE is short for DeadCodeElimination
    # NOTE: reverse order traversal: update vars used into `used_after`
    # if a inst def a var NOT used at `used_after`, mark it as pending delete index set
    used_after: set[AsmArg] = cb.get_all_next_cbs_use_vars(get_current_cb=False)
    # Log.info(f"DCE_cb_reverse START {DEBUG_MSG} cb: {cb} used_after {len(used_after)}")
    insts = cb.insts
    inst_len = cb.inst_len

    # Step-1: add inst that [def a var not in current `used_after`] into pending set (in reverse order)
    pending_delete_inst_idxs: set = set()
    delete_idx_mask = [False] * inst_len
    for i in range(inst_len - 1, -1, -1):
        def_vars_inst, use_vars_inst = insts[i].get_def_use()
        used_after |= use_vars_inst

        # var def in this inst is used after this inst or not
        # if one var in def_vars_inst used, then this inst cannot be deleted
        used_after_flag = any(var in used_after for var in def_vars_inst)
        if (used_after_flag is False):  # all def-ed var in this inst are not used after
            pending_delete_inst_idxs.add(i)
        if (len(def_vars_inst) == 1):
            only_def_var = def_vars_inst.pop()
            if (only_def_var not in use_vars_inst and only_def_var.is_acc()):
                # TODO: more test needed, more situation needed # NOTE: must be placed in the last
                # if a var def in this inst, but: 1. not used in this inst; 2. is ACC
                # e.g. acc = v0 + v1 # for previous inst, acc is not used
                used_after.discard(only_def_var)

        # PHO-reverse
        if (used_after_flag is False or
                i - 1 < 0 or delete_idx_mask[i] or delete_idx_mask[i - 1]):
            continue  # skip if deleted in previous or aready set to True
        pre1_t, curr_t = insts[i - 1], insts[i]
        pre1_def, pre1_use = pre1_t.get_def_use()
        curr_def, curr_use = curr_t.get_def_use()
        len_curr_def, len_pre1_def, len_curr_use = len(curr_def), len(pre1_def), len(curr_use)
        if (len_curr_def):
            var_in_curr_def = curr_def.pop()
        if (len_pre1_def):
            var_in_pre1_def = pre1_def.pop()
        if (len_curr_use):
            var_in_curr_use = curr_use.pop()
        # PHO-reverse: pre1: a=xxx; curr: b=a; a not used later
        if (curr_t.is_simplest_assgin()
                and len_curr_def == len_curr_use == len_pre1_def == 1
                and var_in_pre1_def == var_in_curr_use and var_in_curr_use not in used_after):
            pre1_t.replace_def_var(var_in_curr_def)
            delete_idx_mask[i] = True
            continue
        if (delete_idx_mask[i] == False):
            # def_vars_inst, use_vars_inst = curr_t.get_def_use()  # must update at last
            used_after |= curr_use
            used_after |= {var_in_curr_use}
    cb.set_use_vars(used_after)

    # Step-2: determine: if idxs in pending delete inst idxs actually need to be deleted
    # Log.info(f"DCE_cb_reverse START-MID {DEBUG_MSG} cb: {cb} used_after {len(used_after)}", True)
    tac_l: List[TAC] = [
        inst for i, inst in enumerate(insts)
        if not (  # delete
            i in pending_delete_inst_idxs and
            (inst.type in {TACTYPE.ASSIGN, TACTYPE.IMPORT}) and
            inst.args[0].is_temp_var_like()
        ) and not (
            delete_idx_mask[i]
        ) and not (  # same inst[i] and inst[i+1]
            i + 1 < inst_len and
            inst == insts[i + 1] and
            inst.type in {TACTYPE.COND_THR, TACTYPE.UNCN_THR, TACTYPE.IMPORT}
        ) and not (  # v0 = v0
            inst.is_simplest_assgin() and inst.args[0] == inst.args[1]
        ) and not (  # v0 = v0 + "" or v0 = "" + v0
            inst.rop == "+" and
            inst.type == TACTYPE.ASSIGN and
            len(inst.args) == 3 and
            ((inst.args[0] == inst.args[1] and inst.args[2].is_str_and_eq("")) or
             (inst.args[0] == inst.args[2] and inst.args[1].is_str_and_eq("")))
        )
    ]
    cb.replace_insts(tac_l)
