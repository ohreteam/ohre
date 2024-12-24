from typing import Any, Dict, Iterable, List, Tuple, Union

import ohre.core.ohoperator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.abcre.core.IndexHeader import IndexHeader
from ohre.misc import Log


class IndexSection(BaseRegion):
    def __init__(self, buf, pos: int, num_index_regions: int):
        pos = op._align4(pos)
        super().__init__(pos)
        self.headers: List[IndexHeader] = list()
        for _ in range(num_index_regions):
            index_header, self.pos_end = IndexHeader._get_class_offset(buf, self.pos_end)
            self.headers.append(index_header)
        assert len(self.headers) == num_index_regions

    def __str__(self):
        out_region_headers = ""
        for i in range(len(self.headers)):
            out_region_headers += f"[{i}/{len(self.headers)}]{self.headers[i]}"
        out = f"IndexSection: [{hex(self.pos_start)}/{hex(self.pos_end)}] {out_region_headers}"
        return out
