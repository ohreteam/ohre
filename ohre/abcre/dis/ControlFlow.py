from ohre.abcre.dis.NACBlock import NACBlock
from ohre.abcre.dis.NACBlocks import NACBlocks
from ohre.abcre.dis.NACTYPE import NACTYPE
from ohre.misc import Log, utils


class ControlFlow():
    def split_native_code_block(blocks: NACBlocks) -> NACBlocks:
        assert len(blocks) == 1
        nac_block = blocks.nac_blocks[0]
        delimited_id: list = list()
        for i in range(len(nac_block)):
            nac = nac_block.nacs[i]
            if (nac.type == NACTYPE.LABEL):
                delimited_id.append(i)
            elif (nac.type == NACTYPE.COND_JMP or nac.type == NACTYPE.UNCN_JMP or nac.type == NACTYPE.RETURN):
                if (i + 1 < len(nac_block)):
                    delimited_id.append(i + 1)
        delimited_id = sorted(list(set(delimited_id)))
        if (len(nac_block) not in delimited_id):
            delimited_id.append(len(nac_block))
        debug_out = ""
        for idx in delimited_id:
            if (idx < len(nac_block)):
                debug_out += f"{idx}-{nac_block.nacs[idx]}; "
            else:
                debug_out += f"{idx} nac_block len {len(nac_block)}"
        Log.info(f"[ControlFlow] delimited id-nac {debug_out}", False)

        final_nac_blocks: list = list()
        idx_start = 0
        for i in range(len(delimited_id)):
            idx_end = delimited_id[i]
            final_nac_blocks.append(nac_block.get_slice_block(idx_start, idx_end))
            idx_start = idx_end
        return NACBlocks(final_nac_blocks)
