#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pathlib import Path
from cptools import LogHandler

from .tool_function import read_json, read_pickle

CUR_PATH = Path(__file__).resolve()

logger = LogHandler('DataPrepare')


def load_software_level_feature(home_path, func_name_only=False):
    func_name_path = home_path.joinpath('func_names.json')
    assert func_name_path.exists(), f"can not load func names of {home_path}"
    func_names = read_json(home_path.joinpath('func_names.json'))
    if func_name_only:
        return func_names
    string_path = home_path.joinpath('strings.json')
    assert string_path.exists(), f"can not load strings.json of {home_path}"
    strings = read_json(home_path.joinpath('strings.json'))
    return func_names, strings


def load_bin_features(bin_home_path, only_basic=False):
    """
    Load software level and function level features in bin_home_path
    :param bin_home_path:
    :return:
    """
    bin_feats = {}
    bin_home_path = Path(bin_home_path)
    tmp = read_json(bin_home_path.joinpath('func_names.json'))
    func_names = tmp['func_names']
    imports, exports = set([func_lib[0] for func_lib in tmp['imports']]), set(tmp['exports'])
    strings = set(read_json(bin_home_path.joinpath('strings.json'))['strings_in_rodata'])
    bin_feats['exports'] = exports
    bin_feats['strings'] = strings
    if only_basic:
        return bin_feats
    # self.logger.info(f'Loading function level features: {bin_home_path}')
    try:
        bin_feats['embed_info'] = read_pickle(bin_home_path.joinpath('Asteria_embeddings.pkl'))
    except FileNotFoundError:
        bin_feats['embed_info'] = None
    try:
        bin_feats['call_graph'] = read_pickle(bin_home_path.joinpath('call_graph.pkl'))
    except FileNotFoundError:
        bin_feats['call_graph'] = None
    try:
        # bin_feats['anchor_paths'] = pd.read_csv(bin_home_path.joinpath('anchor_paths.csv'))
        bin_feats['anchor_path_node2eps'] = read_json(bin_home_path.joinpath('anchor_path-node2eps.json'))
        bin_feats['anchor_path_ep2nodes'] = read_json(bin_home_path.joinpath('anchor_path-ep2nodes.json'))
    except FileNotFoundError:
        # bin_feats['anchor_paths'] = None
        bin_feats['anchor_path_node2eps'] = None
        bin_feats['anchor_path_ep2nodes'] = None
    # anchor_paths = None
    try:
        bin_feats['func2ast_depth'] = read_json(bin_home_path.joinpath('func_ast_depth.json'))
    except FileNotFoundError:
        bin_feats['func2ast_depth'] = None

    try:
        bin_feats['func2arg_info'] = read_json(bin_home_path.joinpath('func_args.json'))
    except FileNotFoundError:
        bin_feats['func2arg_info'] = None

    return bin_feats
