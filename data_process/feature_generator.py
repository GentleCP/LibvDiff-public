#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Generate all necessary features based on IDA scripts
"""
import time
from pathlib import Path
from collections import defaultdict
from argparse import ArgumentParser

from cptools import LogHandler

from utils.tool_function import get_bin_info, execute_cmd, read_pickle, read_json, write_json
from utils.multi_process import generate_by_multi_bins
from call_gath_generator import get_anchor_func_path
from settings import IDA64_PATH, IDA_PATH, IS_LINUX, SKIP_SUFFIX, PASS_EXIST


class FeatGenerator(object):
    """
    - software level features
        - function names
        - strings
    - function level features
        - AST used in Asteria
        - call graph
    """

    def __init__(self, process_num=1, pass_exist=True):
        """
        :param process_num: if process_num > 1 use multiprocess
        :return:
        """
        self.process_num = process_num
        self.pass_exist = pass_exist
        self.path2mode = defaultdict(int)
        self.logger = LogHandler('FeatGenerator', file=True)
        self.ida_scripts = {
            'software_level_feature': 'fg_software_level_ida',
            'asteria_feature': 'fg_asteria_ida',
            'call_graph_feature': 'fg_call_graph_ida',
            'func_arg_feature': 'fg_func_args_ida',
        }

    def get_mode(self, bin_path):
        bin_path = str(bin_path)
        if bin_path in self.path2mode.keys():
            return self.path2mode[bin_path]
        else:
            res = get_bin_info(bin_path)
            if res['errcode'] != 0:
                res['bin_path'] = bin_path
                return res
            mode = res['bin_info'].get('mode', 0)
        if mode == '32' or mode == '32-bit':
            self.path2mode[bin_path] = 32
            return 32
        elif mode == '64' or mode == '64-bit':
            self.path2mode[bin_path] = 64
            return 64

    def gen_sl_feature(self, bin_path, **kwargs):
        mode = self.get_mode(bin_path)
        if mode is None:
            return {
                'errcode': 500,
                'errmsg': 'mode error',
                'bin_path': str(bin_path)
            }
        bin_path = Path(bin_path)
        # func_name_path = kwargs.get('func_name_path', bin_path.parent.joinpath(f"{bin_path.name}-func_names.json"))
        # string_path = kwargs.get('string_path', bin_path.parent.joinpath(f"{bin_path.name}-strings.json"))
        func_name_path = kwargs.get('func_name_path', bin_path.parent.joinpath(f"func_names.json"))
        string_path = kwargs.get('string_path', bin_path.parent.joinpath(f"strings.json"))
        if self.pass_exist and func_name_path.exists() and string_path.exists():
            return {
                'errcode': 0,
                'errmsg': 'exist',
                'bin_path': str(bin_path)
            }
        if mode == 32:
            cmd = f'{IDA_PATH} -Llog/{self.ida_scripts["software_level_feature"]}.log -c -A -S"./{self.ida_scripts["software_level_feature"]}.py {func_name_path} {string_path}" {bin_path}'
        else:
            cmd = f'{IDA64_PATH} -Llog/{self.ida_scripts["software_level_feature"]}.log -c -A -S"./{self.ida_scripts["software_level_feature"]}.py {func_name_path} {string_path}" {bin_path}'

        if IS_LINUX:
            cmd = f"TVHEADLESS=1 {cmd}"
        start = time.time()
        exe_res = execute_cmd(cmd, timeout=1200)
        exe_res['time_cost'] = time.time() - start
        exe_res['bin_path'] = str(bin_path)
        return exe_res

    def gen_sl_feats_by_multi_bins(self, bin_paths):
        self.logger.info('Generating software level features...')
        generate_by_multi_bins(bin_paths, gen_method=self.gen_sl_feature, process_num=self.process_num)

    def gen_asteria_feature(self, bin_path):
        bin_path = Path(bin_path)
        mode = self.get_mode(bin_path)
        if mode is None:
            return {
                'errcode': '500',
                'errmsg': 'mode error',
                'bin_path': str(bin_path)
            }
        feature_path = bin_path.parent.joinpath(f'Asteria_features.pkl')
        if self.pass_exist and feature_path.exists():
            return {
                'errcode': 0,
                'errmsg': 'exist',
                'bin_path': str(bin_path)
            }
        if mode == 32:
            cmd = f'{IDA_PATH} -Llog/{self.ida_scripts["asteria_feature"]}.log -c -A -S"./{self.ida_scripts["asteria_feature"]}.py {feature_path}" {bin_path}'
        else:
            cmd = f'{IDA64_PATH} -Llog/{self.ida_scripts["asteria_feature"]}.log -c -A -S"./{self.ida_scripts["asteria_feature"]}.py {feature_path}" {bin_path}'

        if IS_LINUX:
            cmd = f"TVHEADLESS=1 {cmd}"
        exe_res = execute_cmd(cmd, timeout=3600)
        exe_res['bin_path'] = str(bin_path)
        return exe_res

    def gen_func_args(self, bin_path):
        bin_path = Path(bin_path)
        mode = self.get_mode(bin_path)
        if mode is None:
            return {
                'errcode': '500',
                'errmsg': 'mode error',
                'bin_path': str(bin_path)
            }
        feature_path = bin_path.parent.joinpath(f'func_args.json')
        if feature_path.exists():
            return {
                'errcode': 0,
                'errmsg': 'exist',
                'bin_path': str(bin_path)
            }
        if mode == 32:
            cmd = f'{IDA_PATH} -Llog/{self.ida_scripts["func_arg_feature"]}.log -c -A -S"./{self.ida_scripts["func_arg_feature"]}.py {feature_path}" {bin_path}'
        else:
            cmd = f'{IDA64_PATH} -Llog/{self.ida_scripts["func_arg_feature"]}.log -c -A -S"./{self.ida_scripts["func_arg_feature"]}.py {feature_path}" {bin_path}'

        if IS_LINUX:
            cmd = f"TVHEADLESS=1 {cmd}"
        exe_res = execute_cmd(cmd, timeout=3600)
        exe_res['bin_path'] = str(bin_path)
        return exe_res

    def gen_func_ast_depth(self, bin_path):
        bin_path = Path(bin_path)
        feature_path = bin_path.parent.joinpath(f'func_ast_depth.json')
        if self.pass_exist and feature_path.exists():
            return {
                'errcode': 0,
                'errmsg': 'exist',
                'bin_path': str(bin_path)
            }
        try:
            func2ast_info = read_pickle(bin_path.parent.joinpath('Asteria_features.pkl'))
        except FileNotFoundError:
            return {
                'errcode': 404,
                'errmsg': 'Can not find Asteria features',
                'bin_Path': str(bin_path)
            }
        func2ast_depth = {}
        for func, ast_info in func2ast_info.items():
            func2ast_depth[func] = ast_info['ast'].depth()
        write_json(func2ast_depth, feature_path)
        return {
            'errcode': 0,
            'bin_path': str(bin_path)
        }

    def gen_feat_time_cost(self, bin_path):
        bin_path = Path(bin_path)
        feature_path = bin_path.parent.joinpath(f'func_time_cost.json')
        if self.pass_exist and feature_path.exists():
            return {
                'errcode': 0,
                'errmsg': 'exist',
                'bin_path': str(bin_path)
            }
        try:
            func2ast_info = read_pickle(bin_path.parent.joinpath('Asteria_features.pkl'))
            func2embed_info = read_pickle(bin_path.parent.joinpath('Asteria_embeddings.pkl'))
        except FileNotFoundError:
            return {
                'errcode': 404,
                'errmsg': 'Can not find Asteria features',
                'bin_Path': str(bin_path)
            }
        func2time_cost = {}
        for func in func2embed_info.keys():
            func2time_cost[func] = (func2ast_info[func]['time_cost'], func2embed_info[func]['time_cost'])
        write_json(func2time_cost, feature_path)
        return {
            'errcode': 0,
            'bin_path': str(bin_path)
        }

    def gen_call_graph(self, bin_path,):
        bin_path = Path(bin_path)
        mode = self.get_mode(bin_path)
        if mode is None:
            return {
                'errcode': '500',
                'errmsg': 'mode error',
                'bin_path': str(bin_path)
            }
        feat_path = bin_path.parent.joinpath(f'call_graph.pkl')
        if self.pass_exist and feat_path.exists():
            return {
                'errcode': 0,
                'errmsg': 'exist',
            }
        if mode == 32:
            cmd = f'{IDA_PATH} -Llog/{self.ida_scripts["call_graph_feature"]}.log -c -A -S"./{self.ida_scripts["call_graph_feature"]}.py {feat_path}" {bin_path}'
        else:
            cmd = f'{IDA64_PATH} -Llog/{self.ida_scripts["call_graph_feature"]}.log -c -A -S"./{self.ida_scripts["call_graph_feature"]}.py {feat_path}" {bin_path}'

        if IS_LINUX:
            cmd = f"TVHEADLESS=1 {cmd}"

        exe_res = execute_cmd(cmd, timeout=1200)
        exe_res['bin_path'] = str(bin_path)
        return exe_res

    def gen_ap(self, bin_path):
        """
        :param bin_path:
        :return:
        """
        bin_path = Path(bin_path)
        anchor_path = bin_path.parent.joinpath('anchor_paths.csv')
        if self.pass_exist and anchor_path.exists():
            return {
                'errcode': 0,
                'errmsg': 'exist',
            }
        imports = [func_lib[0] for func_lib in read_json(bin_path.parent.joinpath('func_names.json'))['imports']]
        call_graph = read_pickle(bin_path.parent.joinpath('call_graph.pkl'))
        exports = read_json(bin_path.parent.joinpath('func_names.json'))['exports']
        bin_feats = {'call_graph': call_graph, 'exports': exports}
        start = time.time()
        df_ap = get_anchor_func_path(bin_feats, max_path_len=5).query(f'cur_node not in {imports}')
        df_ap.to_csv(anchor_path, index=False)
        cur_node2export_paths = defaultdict(list)
        export_path2cur_nodes = defaultdict(list)
        def update_cur_node2export_path(x):
            # print(x['cur_node'])
            cur_node2export_paths[x['cur_node']].append(f"{x['export']}@{x['path_seq']}")
            export_path2cur_nodes[f"{x['export']}@{x['path_seq']}"].append(x['cur_node'])

        _ = df_ap.apply(update_cur_node2export_path, axis=1)
        time_cost = time.time() - start
        write_json({'time': time_cost}, anchor_path.parent.joinpath('anchor_path_time.json'))
        write_json(cur_node2export_paths, anchor_path.parent.joinpath('anchor_path-node2eps.json'))
        write_json(export_path2cur_nodes, anchor_path.parent.joinpath('anchor_path-ep2nodes.json'))
        return {
            'errcode': 0,
        }

    def gen_fl_feats_by_multi_bins(self, bin_paths):
        self.logger.info('Generating asteria features...')
        generate_by_multi_bins(bin_paths, gen_method=self.gen_asteria_feature, process_num=self.process_num)
        self.logger.info('Generating func ast depths...')
        generate_by_multi_bins(bin_paths, gen_method=self.gen_func_ast_depth, process_num=self.process_num)
        self.logger.info('Generating call graphs...')
        generate_by_multi_bins(bin_paths, gen_method=self.gen_call_graph, process_num=self.process_num)
        self.logger.info('Generating anchor paths...')
        generate_by_multi_bins(bin_paths, gen_method=self.gen_ap, process_num=self.process_num)

    def run(self, bin_paths, software_level=True, function_level=True):
        self.logger.info('Start feature generation')
        if software_level:
            self.gen_sl_feats_by_multi_bins(bin_paths)
        if function_level:
            self.gen_fl_feats_by_multi_bins(bin_paths)
        self.logger.info('Feature generation finished')


def load_bin_paths(oss):
    bin_paths = []
    dataset_path = Path(__file__).parent.joinpath('dataset')
    sorted_versions = read_json(dataset_path.parent.joinpath(f'features/{oss}/sorted_versions.json'))
    for oss_path in dataset_path.iterdir():
        if oss_path.name != oss:
            continue
        for lib_path in oss_path.iterdir():
            for arch_path in lib_path.iterdir():
                for opt_path in arch_path.iterdir():
                    for ver_path in opt_path.iterdir():
                        if ver_path.name not in sorted_versions:
                            continue
                        try:
                            bin_path = [path for path in ver_path.iterdir() if path.suffix not in SKIP_SUFFIX][0]
                        except IndexError:
                            continue
                        bin_paths.append(bin_path)

    return bin_paths


def main():
    # If process_num > 1, the binary features will be generated with multiprocess
    feat_generator = FeatGenerator(process_num=16, pass_exist=PASS_EXIST)
    args = ArgumentParser()
    args.add_argument('-o', '--oss', default='freetype', help='oss')
    arg = args.parse_args()
    bin_paths = load_bin_paths(oss=arg.oss)
    feat_generator.run(bin_paths, software_level=True, function_level=True)


if __name__ == '__main__':
    main()
