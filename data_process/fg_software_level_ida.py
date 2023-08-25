#!/usr/bin/env python
# -*- coding: utf-8 -*-
import idaapi
import idautils
import idc

import time
from pathlib import Path

from utils.tool_function import write_json


def waiting_analysis():
    idaapi.auto_wait()


def filter_useless_func(func_names):
    # return [func for func in func_names if not (re.match('^(sub_)||(__).*', func))]
    return [func for func in func_names if not func.startswith('sub_')]


class FuncnameViewer(object):
    """
    generate function names and imports exports
    """

    def __init__(self):
        self._func_names = []
        self._imports = []
        self._exports = []

    def imports_names_cb(self, ea, name, ord):
        tmp = name.split('@@')
        if len(tmp) == 1:
            self._imports.append([ord, ea, tmp[0], ''])
        else:
            self._imports.append([ord, ea, tmp[0], tmp[1]])
        return True

    def get_imports(self):
        if self._imports:
            return self._imports

        nimps = idaapi.get_import_module_qty()
        for i in range(nimps):
            idaapi.enum_import_names(i, self.imports_names_cb)
        self._imports.sort(key=lambda x: x[2])
        return self._imports

    def get_exports(self):
        if self._exports:
            return self._exports
        self._exports = list(idautils.Entries())
        return self._exports

    def get_func_names(self):
        if self._func_names:
            return self._func_names
        print('gen func names')
        for ea in idautils.Functions():
            self._func_names.append((ea, idc.get_func_name(ea)))
        return self._func_names

    def save(self, save_path, only_name=False):
        if only_name:
            save_data = {
                'func_names': [item[-1] for item in self.get_func_names() if not item[-1].startswith('sub_')],
                'imports': [item[2:] for item in self.get_imports() if not item[2].startswith('sub_')],
                'exports': [item[3] for item in self.get_exports() if not item[3].startswith('sub_')],
            }
        else:
            save_data = {
                'func_names': self.get_func_names(),
                'imports': self.get_imports(),
                'exports': self.get_exports(),
            }

        write_json(save_data, save_path)


class StringViewer(object):
    """
    generate strings.json table list
    """

    def __init__(self):
        self._strings = []
        self._strings_in_rodata = []

    def get_strings(self, rodata=False):
        if self._strings:
            return self._strings_in_rodata if rodata else self._strings
        print('gen strings')
        for s in idautils.Strings():
            seg = idc.get_segm_name(s.ea)
            self._strings.append((s.ea, seg, s.length, s.strtype, str(s)))
            if seg == '.rodata':
                self._strings_in_rodata.append(self._strings[-1])
        return self._strings_in_rodata if rodata else self._strings

    def save(self, save_path, only_name=False):
        if only_name:
            save_data = {
                'strings_all': [item[-1] for item in self.get_strings()],
                'strings_in_rodata': [item[-1] for item in self.get_strings(rodata=True)]
            }
        else:
            save_data = {
                'strings_all': self.get_strings(),
                'strings_in_rodata': self.get_strings(rodata=True),
            }

        write_json(save_data, save_path)


def get_param(index, default):
    """
    从命令行终端获取参数
    :param index:
    :param default:
    :return:
    """
    try:
        return idc.ARGV[index]
    except IndexError:
        return default


def quit_ida(status=0):
    idc.qexit(status)


if __name__ == '__main__':
    waiting_analysis()
    bin_path = Path(idc.get_input_file_path()).resolve()
    func_name_save_path = Path(idc.ARGV[1]) if len(idc.ARGV) > 1 else bin_path.parent.joinpath(
        f"{bin_path.name}_func_names.json")
    strings_save_path = Path(idc.ARGV[2]) if len(idc.ARGV) > 2 else bin_path.parent.joinpath(f"{bin_path.name}_strings.json")
    start = time.time()
    FuncnameViewer().save(save_path=func_name_save_path, only_name=True)
    StringViewer().save(save_path=strings_save_path, only_name=True)
    time_cost = time.time() - start
    write_json({'time': time_cost}, func_name_save_path.parent.joinpath('func_name_str_time.json'))
    quit_ida()
