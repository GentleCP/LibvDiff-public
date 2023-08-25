#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
-----------------File Info-----------------------
Name: fg_call_graph_ida.py
Description: generate callee relations and import export table
Author: GentleCP
Email: me@gentlecp.com
Create Date: 2022/8/31
-----------------End-----------------------------
"""
import re

import idaapi
import idautils
import idc
import time
from pathlib import Path
from collections import defaultdict
from tqdm import tqdm
import networkx as nx
from utils.tool_function import write_pickle, write_json, read_json


class CallViewer(object):
    """
    generate caller and callee for each function
    """

    def __init__(self):
        self.org_call_graph = nx.DiGraph()
        self.call_graph = nx.DiGraph()
        self.func_name2ea = {}
        self._libc_func_path = Path(__file__).resolve().parent.joinpath('libc_functions.json')
        self._libc_funcs = set(read_json(self._libc_func_path))
        self._pass_func_pattern = re.compile(f'.*(__).*')

    @staticmethod
    def is_thunk_func(func_ea, func_name=None):
        if func_name is not None:
            if func_name.startswith('j_') or func_name.startswith('.') or 'got2.plt' in func_name:
                return True
        return bool(idc.get_func_attr(func_ea, idc.FUNCATTR_FLAGS) & idc.FUNC_THUNK)

    def func_name_process(self, func_name):
        """
        - "isra.0" -> ""
        - "part.0" -> ".0"
        :param func_name:
        :return:
        """
        if func_name is None:
            return func_name
        if '.isra.0' in func_name:
            func_name = func_name.replace(".isra.0", "")
        if ".part.0" in func_name:
            # t1_builder_check_points.part.0 ->  t1_builder_check_points_0
            func_name = func_name.replace(".part.", "_")
        if ".constprop.0" in func_name:
            # _bdf_atoul.constprop.0 -> _bdf_atoul
            func_name = func_name.replace(".constprop.0", "")
        return func_name

    def get_original_call_graph(self, ):
        if self.org_call_graph:
            return self.org_call_graph
        bar = tqdm(list(idautils.Functions()))
        for func_ea in bar:
            if func_ea is None:
                continue
            callee_name = self.func_name_process(idaapi.get_func_name(func_ea))
            if callee_name is None:
                continue
            self.func_name2ea[callee_name] = func_ea
            if self._pass_func_pattern.match(callee_name):
                continue
            bar.set_description(f'generate original callers for {callee_name}')
            for caller_ea in idautils.CodeRefsTo(func_ea, 0):
                caller_name = self.func_name_process(idaapi.get_func_name(caller_ea))
                if caller_name:
                    self.org_call_graph.add_node(caller_name, ea=caller_ea)
                    self.org_call_graph.add_node(callee_name, ea=func_ea)
                    if callee_name not in self.org_call_graph[caller_name]:
                        self.org_call_graph.add_edge(caller_name, callee_name, num=1)
                    else:
                        self.org_call_graph[caller_name][callee_name]['num'] += 1

        return self.org_call_graph

    def get_call_graph(self):
        """
        call graph without thunk function
        :return:
        """
        if self.call_graph:
            return self.call_graph
        original_call_graph = self.get_original_call_graph()
        bar = tqdm(original_call_graph.nodes.items())
        for func_name, func_attr in bar:
            # e.g., __do_global_dtors_aux {'ea': 34660}
            bar.set_description(f'generate callers for {func_name}')
            func_ea = func_attr['ea']
            if self.is_thunk_func(func_ea, func_name=func_name):
                # THUNK function, get its callee as the true callee
                try:
                    callee_name = list(original_call_graph[func_name].keys())[0]
                    callee_ea = original_call_graph.nodes[callee_name]['ea']
                except IndexError:
                    # ida fail to extract call relationship from thunk to its callee, because it is called by register
                    disasm = idc.GetDisasm(func_ea)
                    if '#' not in disasm:
                        continue
                    callee_name = disasm.split('#')[-1].strip()
                    # print('fail to extract callee directly, based on register')
            else:
                callee_ea = func_ea
                callee_name = func_name

            # if it is called by a thunk, get its callers by thunk
            caller_names = list(original_call_graph.predecessors(func_name))
            if len(caller_names) == 0:
                continue
            if self.is_thunk_func(original_call_graph.nodes[caller_names[0]]['ea'],
                                                             func_name=caller_names[0]):
                # THUNK function caller, obtain the callers based on thunk
                caller_names = original_call_graph.predecessors(caller_names[0])

            is_libc = False
            for part in callee_name.split('_'):
                if part in self._libc_funcs:
                    is_libc = True
            if is_libc:
                continue

            if self._pass_func_pattern.match(callee_name):
                continue

            for caller_name in caller_names:
                self.call_graph.add_node(caller_name, ea=original_call_graph.nodes[caller_name]['ea'])
                try:
                    self.call_graph.add_node(callee_name, ea=original_call_graph.nodes[callee_name]['ea'])
                except KeyError:
                    # can not find func in original graph, add node by name
                    self.call_graph.add_node(callee_name, ea=self.func_name2ea[callee_name])
                if callee_name not in self.call_graph[caller_name]:
                    self.call_graph.add_edge(caller_name, callee_name, num=1)
                else:
                    self.call_graph[caller_name][callee_name]['num'] += 1

        return self.call_graph


def main():
    start = time.time()
    call_graph = CallViewer().get_call_graph()
    time_cost = time.time() - start

    if len(idc.ARGV) == 2:
        save_path = Path(idc.ARGV[1])
    else:
        bin_path = Path(idc.get_input_file_path()).resolve()
        save_path = bin_path.parent.joinpath(f'call_graph.pkl')

    write_pickle(call_graph, save_path)
    write_json({'time': time_cost}, save_path.parent.joinpath('call_graph_time.json'))


if __name__ == '__main__':
    idaapi.auto_wait()
    main()
    idc.qexit(0)
