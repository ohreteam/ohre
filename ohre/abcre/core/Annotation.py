from typing import Any, Dict, Iterable, List, Tuple

import ohre.core.operator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.abcre.core.Field import Field
from ohre.abcre.core.Method import Method
from ohre.abcre.core.TaggedValue import TaggedValue
from ohre.abcre.enum.ClassTag import ClassTag
from ohre.abcre.enum.SourceLanguage import SourceLanguage
from ohre.misc import Log


class Annotation(BaseRegion):
    def __init__(self, buf, annotation_offsets: tuple):
        self.start_offset = op._uint8_t_array_to_int(annotation_offsets)
        # class_idx	uint16_t
        self.class_idx,self.pos_end = op._read_uint16_t_offset(buf,self.start_offset)
        # count	uint16_t
        self.count,self.pos_end = op._read_uint16_t_offset(buf,self.pos_end)
        # elements	AnnotationElement[]
        self.elements,self.pos_end = _read_annotation_elements(buf,self.count,self.pos_end)
        # element_types	uint8_t[]
        self.element_types,self.pos_end = _read_element_types(buf,self.count,self.pos_end)

    def __str__(self):
        elements_output = []
        for i, elem in enumerate(self.elements):
            elements_output.append(f"{i}-th name_off:{hex(elem[0])}, {elem[0]}, element_value:{hex(elem[2])}, {elem[2]}")
        elements_output = ";".join(elements_output)

        element_types_output = []
        for i, elet in enumerate(self.element_types):
            element_types_output.append(f"{i}-th {hex(elet)}, {elet}")
        element_types_output = ";".join(element_types_output)

        out_debuginfo_data = f"Annotation Start Offfset: {hex(self.start_offset)},{self.start_offset} class_idx: {hex(self.class_idx)}, {self.class_idx} \
count: {hex(self.count)} {self.count} elements: {elements_output} element_types: {element_types_output}"
        return out_debuginfo_data

def _read_annotation_elements(buf,count,pos_end):
    elements_array = []
    for _ in range(count):
        # name_off	uint32_t
        name_off,pos_end = op._read_uint32_t_offset(buf,pos_end)
        element_name = op._read_String(buf,name_off)
        # value	uint32_t
        value,pos_end = op._read_uint32_t_offset(buf,pos_end)
        elements_array.append([name_off,element_name,value])
    return elements_array,pos_end

def _read_element_types(buf,count,pos_end):
    element_types_array = []
    for _ in range(count):
        et_,pos_end = op._read_uint8_t_offset(buf,pos_end)
        element_types_array.append(et_)
    return element_types_array,pos_end

