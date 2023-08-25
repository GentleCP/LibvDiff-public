#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Generate version difference cheat sheet(VDCS)
"""
import re

from argparse import ArgumentParser
from cptools import LogHandler
from pathlib import Path
from tqdm import tqdm
from collections import defaultdict, OrderedDict
from pydriller import Git, Repository
from utils.data_prepare import load_software_level_feature
from utils.tool_function import read_json, write_json, get_tags_by_repo


def make_version_pairs(comp_versions):
    """
    基于一定策略生成不同版本对
    :param comp_versions:
    :return:
    """
    pairs = []
    for i, v1 in enumerate(comp_versions):
        for j, v2 in enumerate(comp_versions[i + 1:]):
            pairs.append(f"{v1}@{v2}")
    return pairs


class VDCSGenerator(object):
    """
    Extract version difference and generate VDCS
    """

    def __init__(self):
        self.logger = LogHandler('VDCSGenerator')
        self.comment_pattern = re.compile('(/\*[\w\W]*?\*/|//.*?$|//.*?$)')
        self.str_pattern = re.compile('".*?"')
        self.version_diff_path = None
        self.source_code_path = None

    @staticmethod
    def load_oss_level_feature(basic_feat_dir):
        version2lib2func_names = defaultdict(dict)
        version2lib2strings = defaultdict(dict)

        for lib_path in basic_feat_dir.iterdir():
            lib = lib_path.name
            for ver_path in lib_path.joinpath('ARM/O2/').iterdir():
                if ver_path.name.startswith('.'):
                    continue
                version = ver_path.name
                if ver_path.is_file():
                    continue
                func_names, strings = load_software_level_feature(home_path=ver_path, func_name_only=False)
                version2lib2strings[version][lib] = strings['strings_in_rodata']
                version2lib2func_names[version][lib] = func_names['func_names']
        return version2lib2func_names, version2lib2strings

    def get_changed_feats(self, commits):
        """
        find changed functions and strings in source code
        :return:
        """
        changed_methods = set()
        changed_strs = set()
        for commit in tqdm(commits, desc=f'analyse commits'):
            # for commit in commits:
            for m_f in commit.modified_files:
                if m_f.filename.split('.')[-1] not in ['c', 'cpp', 'cxx', 'h']:
                    continue
                if self.func_diff:
                    changed_methods = changed_methods.union(
                        set([m.name for m in m_f.changed_methods]))
                if self.str_diff:
                    changed_data = m_f.diff_parsed
                    for line_num, data in changed_data['added']:
                        data_without_comment = self.comment_pattern.sub('', data)
                        res = self.str_pattern.search(data_without_comment)
                        if res:
                            change_str = res.group()[1:-1]
                            if len(change_str) < 5:
                                continue
                            # changed_strs.add((data, change_str.replace('\\n', '\n')))
                            changed_strs.add(change_str.replace('\\n', '\n'))

                    for line_num, data in changed_data['deleted']:
                        data_without_comment = self.comment_pattern.sub('', data)
                        res = self.str_pattern.search(data_without_comment)
                        if res:
                            change_str = res.group()[1:-1]
                            if len(change_str) < 5:
                                continue
                            # changed_strs.add((data, change_str.replace('\\n', '\n')))
                            changed_strs.add(change_str.replace('\\n', '\n'))

        return list(changed_methods), list(changed_strs)
        # return {version_pair: list(changed_methods)}

    @staticmethod
    def gen_vp_diffs_of_two_version(changed_feats, old_lib2feats, new_lib2feats):
        """
        对所提供的methods根据其在二进制函数前后两个版本中出现的情况，判断其类型
        :return:
        """
        diff_between_versions = defaultdict(dict)
        # 检验函数名是否在新旧两个版本中，判断差异类型
        for lib in old_lib2feats.keys():
            try:
                old_feats = set(old_lib2feats[lib])
                new_feats = set(new_lib2feats[lib])
            except KeyError:
                # lib必须拥有相应版本
                continue
            # 同时位于三个集合的是更新
            diff_between_versions[lib]['update'] = list(changed_feats.intersection(old_feats.intersection(new_feats)))
            # 位于old但不位于new
            diff_between_versions[lib]['delete'] = list(changed_feats.intersection(old_feats.difference(new_feats)))
            # 位于new但不位于old
            diff_between_versions[lib]['add'] = list(changed_feats.intersection(new_feats.difference(old_feats)))

        return diff_between_versions

    def _get_adj_version_pair2changed_feats(self):
        """
        Extract version sensitive methods and strings between adjacent versions
        :return:
        """
        self.logger.info('Generating adjacent version pairs changed methods...')

        adj_vp2func_diff_save_path = self.version_diff_path.joinpath('adj_vp2changed_methods.json')
        adj_vp2str_diff_save_path = self.version_diff_path.joinpath('adj_vp2changed_strs.json')
        if adj_vp2func_diff_save_path.exists():
            self.logger.info('changed methods exist, loading...')
            adj_version_pair2changed_methods = read_json(adj_vp2func_diff_save_path)
        else:
            adj_version_pair2changed_methods = OrderedDict()
        if adj_vp2str_diff_save_path.exists():
            self.logger.info('changed strings exist, loading...')
            adj_version_pair2changed_strs = read_json(adj_vp2str_diff_save_path)
        else:
            adj_version_pair2changed_strs = OrderedDict()

        bar = tqdm(range(len(self.tags) - 1))
        for i in bar:
            version_pair = f"{self.tags[i]}@{self.tags[i + 1]}"
            bar.set_description(f"getting changed feats of {version_pair}")
            if version_pair in adj_version_pair2changed_methods.keys() and version_pair in adj_version_pair2changed_strs.keys():
                continue
            repo = Repository(str(self.source_code_path),
                              from_tag=self.tags[i],
                              to_tag=self.tags[i + 1],
                              only_modifications_with_file_types=['.c', '.cpp', '.cxx', '.h'],
                              )
            commits = list(repo.traverse_commits())
            try:
                if commits[0].hash == Git(str(self.source_code_path)).get_commit_from_tag(self.tags[i]).hash:
                    # bypass from tag commit
                    commits = commits[1:]
            except IndexError:
                # 版本之间没有相关文件改动
                adj_version_pair2changed_methods[version_pair] = []
                adj_version_pair2changed_strs[version_pair] = []
            else:
                changed_methods, changed_strs = self.get_changed_feats(commits, )
                adj_version_pair2changed_methods[version_pair] = changed_methods
                adj_version_pair2changed_strs[version_pair] = changed_strs

        if self.func_diff:
            write_json(adj_version_pair2changed_methods, adj_vp2func_diff_save_path)
        if self.str_diff:
            write_json(adj_version_pair2changed_strs, adj_vp2str_diff_save_path)
        # return adj_version_pair2changed_methods
        return adj_version_pair2changed_methods, adj_version_pair2changed_strs

    def _gen_vp_diffs(self,
                      version_pairs,
                      version2index,
                      adj_vp2changed_feats,
                      version2lib2feats,
                      vp_type,
                      ):
        """
        Generate vp func diffs based on version sensitive functions:
        - add
        - delete
        - update
        - other
        :return:
        """
        all_lib2diffs = defaultdict(dict)
        bar = tqdm(version_pairs)
        for pair in bar:
            bar.set_description(f"Generating version diffs for pair:{pair}")
            # 对任意的两两版本对，确认修改method的类型
            old_v, new_v = pair.split('@')
            start_index = version2index[old_v]
            end_index = version2index[new_v]
            cur = start_index
            changed_feats = set()

            while cur < end_index:
                changed_feats = changed_feats.union(
                    set(adj_vp2changed_feats.get(f"{self.tags[cur]}@{self.tags[cur + 1]}", [])))
                cur += 1
            lib2diffs = self.gen_vp_diffs_of_two_version(changed_feats=changed_feats,
                                                         old_lib2feats=version2lib2feats[old_v],
                                                         new_lib2feats=version2lib2feats[new_v])
            for lib, diffs in lib2diffs.items():
                # diffs: add: [],...
                all_lib2diffs[lib][pair] = (
                    diffs.get('add', []),
                    diffs.get('delete', []),
                    diffs.get('update', []),
                )
        for lib, all_diffs_of_lib in all_lib2diffs.items():
            # different lib diffs save in different files
            vp_diff_path = self.version_diff_path.joinpath(f"vp_diffs-{vp_type}-{lib}.json")
            self.logger.info(f'saving version pair to func diffs into local file:{vp_diff_path}')
            write_json(all_diffs_of_lib, vp_diff_path)

    def get_sorted_versions(self, allow_versions=None, tag_pattern=None):
        return get_tags_by_repo(self.source_code_path,
                                allow_versions=allow_versions,
                                tag_pattern=tag_pattern)

    def run(self, oss, src_code_path, basic_feat_dir, version_diff_path, func_diff=True, str_diff=True):
        self.logger.info(f"Generating VDCS for {oss}")
        self.version_diff_path = Path(version_diff_path)
        self.func_diff, self.str_diff = func_diff, str_diff
        self.version_diff_path.mkdir(exist_ok=True)
        self.source_code_path = Path(src_code_path)
        assert self.source_code_path.exists(), f"source code path not exist"
        version2lib2func_names, version2lib2strings = self.load_oss_level_feature(
            basic_feat_dir=Path(basic_feat_dir))
        self.tags = read_json(self.version_diff_path.parent.joinpath('sorted_versions.json'))
        # self.tags = self.get_sorted_versions(allow_versions=version2lib2func_names.keys())
        # self.tags = sorted(list(version2lib2func_names.keys()))
        assert len(self.tags) > 0, f"can not get tags of {oss}"
        version2index = {v: i for i, v in enumerate(self.tags)}  # 通过版本获取对应下标
        version_pairs = make_version_pairs(self.tags)

        adj_vp2changed_methods, adj_vp2changed_strs = self._get_adj_version_pair2changed_feats()

        if self.func_diff:
            self._gen_vp_diffs(version_pairs=version_pairs,
                               version2index=version2index,
                               adj_vp2changed_feats=adj_vp2changed_methods,
                               version2lib2feats=version2lib2func_names,
                               vp_type='func')
        if self.str_diff:
            self._gen_vp_diffs(version_pairs=version_pairs,
                               version2index=version2index,
                               adj_vp2changed_feats=adj_vp2changed_strs,
                               version2lib2feats=version2lib2strings,
                               vp_type='str')


def main():
    generator = VDCSGenerator()
    args = ArgumentParser()
    args.add_argument('-o', '--oss', default='freetype', help='oss')
    arg = args.parse_args()

    generator.run(oss=arg.oss,
                  src_code_path=Path(f'features/{arg.oss}/{arg.oss}-code'),
                  basic_feat_dir=Path(f'dataset/{arg.oss}/'),
                  version_diff_path=Path(f'features/{arg.oss}/version-diff'),
                  func_diff=True,
                  str_diff=True)

if __name__ == '__main__':
    main()
