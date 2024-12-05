from typing import Any, Dict, Iterable, List, Tuple

import ohre.core.operator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.abcre.core.RegionHeader import RegionHeader
from ohre.misc import Log


class RegionIndex(BaseRegion):
    def __init__(self, buf, pos: int, num_index_regions: int):
        pos = op._align4(pos)
        super().__init__(pos)
        self.arrRegionHeader: List[RegionHeader] = list()
        for i in range(num_index_regions):
            region_header, self.pos_end = RegionHeader._get_class_offset(buf, self.pos_end)
            self.arrRegionHeader.append(region_header)

    def __str__(self):
        out_region_headers = ""
        for i in range(len(self.arrRegionHeader)):
            out_region_headers += f"[{i}/{len(self.arrRegionHeader)}]{self.arrRegionHeader[i]}"
        out = f"RegionIndex: [{hex(self.pos_start)}/{hex(self.pos_end)}] {out_region_headers}"
        return out
