import ohre.core.operator as op
from ohre.abcre.core.BaseRegion import BaseRegion
from ohre.abcre.enum.ClassTag import ClassTag
from ohre.abcre.core.Field import Field
from ohre.abcre.core.Method import Method
from ohre.abcre.core.TaggedValue import TaggedValue
from typing import Any, Dict, List, Tuple, Iterable
from ohre.misc import Log


class Class(BaseRegion):
    def __init__(self, buf, pos: int = 0):
        super().__init__(pos)
        self.name, self.pos_end = op._read_String_offset(buf, self.pos_end)
        self.super_class_off, self.pos_end = op._read_uint8_t_array_offset(buf, self.pos_end, 4)
        self.access_flags, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)
        self.num_fields, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)
        self.num_methods, self.pos_end = op._read_uleb128_offset(buf, self.pos_end)
        # TaggedValue[] end with ClassTag.NOTHING 0x00
        self.class_data, self.pos_end = _read_class_data_TaggedValue(buf, self.pos_end)
        # Field[] cnt=num_fields
        self.fields, self.pos_end = _read_Field_array(buf, self.pos_end, self.num_fields)
        # Method[] cnt=num_methods
        self.methods: Iterable[Class] = None
        self.methods, self.pos_end = _read_Method_array(buf, self.pos_end, self.num_methods)

    def __str__(self):
        out_tag_value = ""
        for t_v in self.class_data:
            out_tag_value += f"{t_v}; "
        out_fields = ""
        for i in range(len(self.fields)):
            out_fields += f"[{i}] {self.fields[i]}; "
        out_methods = ""
        for i in range(len(self.methods)):
            out_methods += f"\n[{i}] {self.methods[i]}; "
        out = f"Class: [{hex(self.pos_start)}/{hex(self.pos_end)}] name {self.name} \
super_class_off {self.super_class_off} access_flags {hex(self.access_flags)} \
num_fields {hex(self.num_fields)} num_methods {hex(self.num_methods)}\n\
class_data({len(self.class_data)}) {out_tag_value}\n\
fields({len(self.fields)}) {out_fields}\n\
methods({len(self.methods)}) {out_methods}"
        return out


def _read_ClassTag_INTERFACES(buf, offset):
    num_INTERFACES, offset = op._read_uleb128_offset(buf, offset)
    data_INTERFACES, offset = op._read_uint8_t_array_offset(buf, offset, num_INTERFACES)
    return num_INTERFACES, data_INTERFACES, offset


def _read_class_data_TaggedValue(buf, offset) -> Tuple[list[TaggedValue], int]:
    l_tag_value = list()
    while (True):
        tag, offset = op._read_uint8_t_offset(buf, offset)
        Log.debug(f"_read_class_data_TaggedValue tag/offset {tag}/{hex(offset)}")
        t_v = TaggedValue(-1)
        if (tag == ClassTag.NOTHING):
            t_v = TaggedValue(ClassTag.NOTHING)
        elif (tag == ClassTag.INTERFACES):
            num_INTERFACES, data_INTERFACES, offset = _read_ClassTag_INTERFACES(buf, offset)
            t_v = TaggedValue(ClassTag.INTERFACES)  # TODO:
            print(f"num_INTERFACES {num_INTERFACES} data_INTERFACES {data_INTERFACES} offset {offset}")
        elif (tag == ClassTag.SOURCE_LANG):
            SOURCE_LANG, offset = op._read_uint8_t_offset(buf, offset)
            t_v = TaggedValue(ClassTag.SOURCE_LANG, SOURCE_LANG)
        elif (tag == ClassTag.RUNTIME_ANNOTATION):
            RUNTIME_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(ClassTag.RUNTIME_ANNOTATION, RUNTIME_ANNOTATION)
        elif (tag == ClassTag.ANNOTATION):
            ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(ClassTag.ANNOTATION, ANNOTATION)
        elif (tag == ClassTag.RUNTIME_TYPE_ANNOTATION):
            RUNTIME_TYPE_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(ClassTag.RUNTIME_TYPE_ANNOTATION, RUNTIME_TYPE_ANNOTATION)
        elif (tag == ClassTag.TYPE_ANNOTATION):
            TYPE_ANNOTATION, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(ClassTag.TYPE_ANNOTATION, TYPE_ANNOTATION)
        elif (tag == ClassTag.SOURCE_FILE):
            SOURCE_FILE, offset = op._read_uint8_t_array_offset(buf, offset, 4)
            t_v = TaggedValue(ClassTag.SOURCE_FILE, SOURCE_FILE)
        else:
            Log.error(f"_read_class_data_TaggedValue: tag NOT supported {tag} offset {offset}")
            exit()

        l_tag_value.append(t_v)
        if (tag == ClassTag.NOTHING):
            break
    return l_tag_value, offset


def _read_Field_array(buf, offset, num_fields) -> Tuple[list[Field], int]:
    l_field = list()
    for i in range(num_fields):
        field = Field(buf, offset)
        offset = field.pos_end
        l_field.append(field)
    return l_field, offset


def _read_Method_array(buf, offset, num_methods) -> Tuple[list[Method], int]:
    l_method = list()
    for i in range(num_methods):
        method = Method(buf, offset)
        offset = method.pos_end
        l_method.append(method)
    return l_method, offset
