#!/usr/bin/env/ python
# -*- coding: utf-8 -*-
import struct
from typing import Dict
from ohre.misc import Log

class ResType:
    ELEMENT = 0
    RAW = 6
    INTEGER = 8
    STRING = 9
    STRARRAY = 10
    INTARRAY = 11
    BOOLEAN = 12
    COLOR = 14
    ID = 15
    THEME = 16
    PLURAL = 17
    FLOAT = 18
    MEDIA = 19
    PROF = 20
    PATTERN = 21
    SYMBOL = 23
    RES = 24

    def __init__(self, value):
        self.value = value

    def __str__(self):
        if self.value == ResType.ELEMENT:
            return "ELEMENT"
        elif self.value == ResType.RAW:
            return "RAW"
        elif self.value == ResType.INTEGER:
            return "INTEGER"
        elif self.value == ResType.STRING:
            return "String"  # 返回 "String"
        elif self.value == ResType.STRARRAY:
            return "STRARRAY"
        elif self.value == ResType.INTARRAY:
            return "INTARRAY"
        elif self.value == ResType.BOOLEAN:
            return "BOOLEAN"
        elif self.value == ResType.COLOR:
            return "COLOR"
        elif self.value == ResType.ID:
            return "ID"
        elif self.value == ResType.THEME:
            return "THEME"
        elif self.value == ResType.PLURAL:
            return "PLURAL"
        elif self.value == ResType.FLOAT:
            return "FLOAT"
        elif self.value == ResType.MEDIA:
            return "MEDIA"
        elif self.value == ResType.PROF:
            return "PROF"
        elif self.value == ResType.PATTERN:
            return "PATTERN"
        elif self.value == ResType.SYMBOL:
            return "SYMBOL"
        elif self.value == ResType.RES:
            return "RES"
        else:
            return f"UNKNOWN{self.value}"


class KeyParam:
    TYPE_LANGUAGE = 0
    TYPE_REGION = 1
    TYPE_RESOLUTION = 2
    TYPE_ORIENTATION = 3
    TYPE_DEVICETYPE = 4
    TYPE_NIGHTMODE = 6
    TYPE_MCC = 7
    TYPE_MNC = 8

    def __init__(self, raw):
        self.raw = raw

    @property
    def key_type(self):
        return self.raw & 0xffffffff

    @property
    def value(self):
        return self.raw >> 32

    def __str__(self):
        key_type = self.key_type
        value = self.value
        if key_type == self.TYPE_ORIENTATION:
            return "vertical" if value == 0 else "horizontal"
        elif key_type == self.TYPE_NIGHTMODE:
            return "dark" if value == 0 else "light"
        elif key_type == self.TYPE_DEVICETYPE:
            return f"device{value}"
        elif key_type == self.TYPE_RESOLUTION:
            return f"dpi{value}"
        elif key_type == self.TYPE_LANGUAGE:
            return f"Language"
        elif key_type == self.TYPE_REGION:
            return f"Region"
        return f"keyType:{key_type} value:{value}"

class IdOffset:
    def __init__(self, raw):
        self.raw = raw

    @property
    def id(self):
        return self.raw & 0xFFFFFFFF

    @property
    def offset(self):
        return (self.raw >> 32) & 0xFFFFFFFF

class ResIndexBuf:
    def __init__(self, buf):
        self.pos = 0
        self.buf = buf
        self.header = self.read_header()
        self.limit_key_configs = self.get_limit_key_configs()
        self.id_set = self.get_id_set()
        self.resource_items = self.get_resources_items()


    def read_header(self)->Dict:
        version = self.buf[:128]
        file_size, limit_key_config_count = struct.unpack('<II', self.buf[128:136])
        version_str = version.decode('utf-8', 'ignore').rstrip('\x00')
        Log.info(f"{version_str}, {file_size}, and the limit_key_config_count is {limit_key_config_count}")
        return {"version": version_str, "file_size": file_size, "limit_key_config_count": limit_key_config_count}


    def get_limit_key_configs(self)->Dict:
        limit_key_configs = {}
        offset = self.pos+136
        for i in range(self.header["limit_key_config_count"]):
            offset += 4

            k_offset = struct.unpack('<i', self.buf[offset:offset + 4])[0]
            offset += 4
            key_count = struct.unpack('<I', self.buf[offset:offset + 4])[0]
            offset += 4

            params = []
            if key_count==0:
                params = ['base']

            else:
                for _ in range(key_count):

                    key_type = self.buf[offset:offset+4]
                    key_value = self.buf[offset+4:offset+8]

                    key_type = struct.unpack('I', key_type)[0]
                    key_value = struct.unpack(f'{len(key_value)}s',key_value)

                    key_value = key_value[0].decode('utf-8').rstrip('\x00')[::-1]
                    offset+=8

                    params.append(str(KeyParam(key_type))+': '+key_value)
            limit_key_configs[k_offset] = params
        Log.info(f"The account of limit_key_configs is {len(limit_key_configs)} and the offset is {offset}")
        self.pos = offset

        return limit_key_configs


    def get_id_set(self)->Dict:
        id_set_map = {}
        offset = self.pos

        for i in range(self.header["limit_key_config_count"]):
            offset+=4

            id_count = self.buf[offset:offset+4]
            id_count = struct.unpack('<i', id_count)[0]
            offset+=4
            for _ in range(id_count):
                values = struct.unpack('<Q', self.buf[offset:offset + 8])[0]
                values = IdOffset(values)
                id_set_map[values.id] = values.offset
                offset+=8
        Log.info(f"The account of id_set_map is {len(id_set_map)} and the offset is {offset}")

        self.pos = offset

        return id_set_map

    def get_resources_items(self)->Dict:
        id_set = self.id_set
        resource_item_dict = {}
        for rid, ridx in id_set.items():
            offset = ridx
            size = struct.unpack_from('<I',self.buf,offset)[0]
            offset+=4

            res_type = struct.unpack_from('<I',self.buf,offset)[0]
            offset+=4

            res_id = struct.unpack_from('<I',self.buf,offset)[0]
            offset+=4

            data_size = struct.unpack_from('<H',self.buf,offset)[0]
            offset+=2

            data_value = self.buf[offset:offset+data_size]
            offset+=data_size

            name_size = struct.unpack_from('<H', self.buf, offset)[0]
            offset += 2

            name_value = self.buf[offset:offset + name_size]
            offset += name_size
            resource_item_dict[res_id]={"file_size":size,"file_type":str(ResType(res_type)),"file_value":data_value.decode('utf-8').strip('\x00'),"file_name":name_value.decode('utf-8').strip('\x00')}
        Log.info(f"The account of resource_item_dict is {len(resource_item_dict)} and the offset is {offset}")

        return resource_item_dict