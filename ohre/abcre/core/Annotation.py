from typing import Any, Dict, Iterable, List, Tuple

import ohre.core.ohoperator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.abcre.core.String import String
from ohre.abcre.core.TaggedValue import TaggedValue
from ohre.abcre.enum.AnnotationElementTag import AnnotationElementTag
from ohre.misc import Log


class Annotation(BaseRegion):
    def __init__(self, buf, pos: int):
        super().__init__(pos)
        self.class_idx, self.pos_end = op._read_uint16_t_offset(buf, self.pos_end)
        self.count, self.pos_end = op._read_uint16_t_offset(buf, self.pos_end)
        self.elements: List[AnnotationElement] = None
        self.elements, self.pos_end = _read_annotation_elements(buf, self.count, self.pos_end)
        # element_types	uint8_t[]
        self.element_types, self.pos_end = _read_element_types(buf, self.count, self.pos_end)
        assert len(self.elements) == self.count
        assert len(self.element_types) == self.count

    def __str__(self):
        out_elements = []
        for elem in self.elements:
            out_elements.append(f"{elem.debug_short()}")
        out_elements = ";".join(out_elements)

        element_types_output = []
        for elet in self.element_types:
            element_types_output.append(f"{AnnotationElementTag.get_type_str(elet)}")
        element_types_output = ";".join(element_types_output)

        out = f"Annotation: [{hex(self.pos_start)}/{hex(self.pos_end)}] class_idx {hex(self.class_idx)} \
count {hex(self.count)} elements({len(self.elements)}): {out_elements} \
element_types({len(self.element_types)}): {element_types_output}"
        return out


def _read_annotation_elements(buf, count, pos_end):
    elements_array = []
    for _ in range(count):
        ae = AnnotationElement(buf, pos_end)
        elements_array.append(ae)
        pos_end = ae.pos_end
    return elements_array, pos_end


def _read_element_types(buf, count, pos_end):
    element_types_array = []
    for _ in range(count):
        et_, pos_end = op._read_uint8_t_offset(buf, pos_end)
        element_types_array.append(et_)
    return element_types_array, pos_end


class AnnotationElement(BaseRegion):  # TODO: support Value formats longger than 32bit
    def __init__(self, buf, pos: int):
        super().__init__(pos)
        self.name_off, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)
        self.name = String(buf, self.name_off)
        self.value, self.pos_end = op._read_uint32_t_offset(buf, self.pos_end)

    def __str__(self):
        out = f"AnnotationElement: [{hex(self.pos_start)}/{hex(self.pos_end)}] {self.name.get_str()} \
name_off {hex(self.name_off)} value {hex(self.value)}"
        return out

    def debug_short(self):
        return f"{self.name.get_str()} {hex(self.value)}"
