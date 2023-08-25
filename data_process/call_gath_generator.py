#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import pandas as pd
import networkx as nx
from tqdm import tqdm
from queue import Queue
from collections import defaultdict


def get_path_seq(path):
    seq = []
    for node_info in path:
        seq.append(node_info['cat'])
    return seq


def get_anchor_func_path(bin_feats, max_path_len=5):
    path_record = defaultdict(dict)
    cg = bin_feats['call_graph']
    datas = []
    for f_e in tqdm(bin_feats['exports'], desc=f'gen func path...'):
        path_record[f_e][f_e] = ()
        q = Queue()
        visited = set()
        q.put(f_e)
        visited.add(f_e)

        while not q.empty():
            cur_node = q.get()
            try:
                callees = list(cg.successors(cur_node))
                callers = list(cg.predecessors(cur_node))
            except nx.NetworkXError:
                continue
            if cur_node != f_e:
                if not cur_node.startswith('.') and not cur_node.startswith('j_'):
                    datas.append((f_e, cur_node, path_record[cur_node][f_e],
                                  get_path_seq(path_record[cur_node][f_e]), len(path_record[cur_node][f_e])))

            for callee in callees:
                if re.match('(__).*', callee) or callee in bin_feats['exports']:
                    continue
                path_record[callee][f_e] = path_record[cur_node][f_e] + ({'node': callee, 'cat': 'e'},)
                if callee not in visited:
                    q.put(callee)
                    visited.add(callee)

            for caller in callers:
                if re.match('(__).*', caller) or caller in bin_feats['exports']:
                    continue
                path_record[caller][f_e] = path_record[cur_node][f_e] + ({'node': caller, 'cat': 'r'},)
                if caller not in visited:
                    q.put(caller)
                    visited.add(caller)

    df_paths = pd.DataFrame(datas, columns=['export', 'cur_node', 'path', 'path_seq', 'path_len'])
    return df_paths.query(f'path_len <= {max_path_len}')
