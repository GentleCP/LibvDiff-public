#!/usr/bin/env python
# -*- coding: utf-8 -*-
import hashlib
import sys
import json
from typing import Union
import pickle as pkl
from pathlib import Path
import subprocess
from collections import OrderedDict

try:
    from pydriller import Git
    import torch
except ModuleNotFoundError:
    pass


def read_json(file_path: Union[str, Path], **kwargs) -> OrderedDict:
    """Read json data into python dict
    Args:
        file_path: file save path
        **kwargs: other parameters used in open()
    Returns:
        json content
    """
    file_path = Path(file_path)
    with file_path.open('rt', **kwargs) as handle:
        return json.load(handle, object_hook=OrderedDict)


def write_json(content: dict, file_path: Union[str, Path], **kwargs):
    """Write dict into json file
    Args:
        content: data dict
        file_path: file save path
        **kwargs: other parameters used in open()
    Returns:
        None
    """
    file_path = Path(file_path)
    with file_path.open('wt', **kwargs) as handle:
        json.dump(content, handle, indent=4, sort_keys=True)


def read_pickle(file_path: Union[str, Path], **kwargs) -> object:
    """Read content of pickle file
    Args:
        file_path: file save path
        **kwargs: other parameters used in open()
    Returns:
        content of pickle file
    """
    file_path = Path(file_path)
    with file_path.open('rb', **kwargs) as handle:
        return pkl.load(handle)


def write_pickle(content: object, file_path: Union[str, Path], **kwargs):
    """Write content to pickle file
    Args:
        content: python object
        file_path: file save path
        **kwargs: other parameters used in open()
    Returns:
        None
    """
    file_path = Path(file_path)
    with file_path.open('wb', **kwargs) as handle:
        pkl.dump(content, handle)


def execute_cmd(cmd, timeout=900):
    """
    execute system command
    :param cmd:
    :param f: 用于指定输出到文件显示，方便后台追踪长时间运行的程序
    :param timeout:
    :return:
    """
    try:
        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout)

    except subprocess.TimeoutExpired as e:
        return {
            'errcode': 401,
            'errmsg': 'timeout'
        }
    return {
        'errcode': p.returncode,
        'errmsg': p.stdout.decode()
    }


def get_bin_info(bin_path: Union[str, Path]):
    """基于die获取binary的基本信息
    :param bin_path:
    :return:
    """
    if sys.platform != 'linux':
        cmd = f"diec.exe {bin_path} -j"
        execute_res = execute_cmd(cmd)
        if execute_res['errcode'] == 0:
            bin_info = json.loads(execute_res['errmsg'])
            if not ('ELF' in bin_info['filetype'] or 'PE' in bin_info['filetype']):
                return {
                    'errcode': 400,
                    'errmsg': f"{bin_path} is not a binary"
                }
            return {
                'errcode': 0,
                'bin_info': bin_info
            }

        return {
            'errcode': 401,
            'errmsg': f"Command execute failed:{execute_res['errmsg']}"
        }
    else:
        # file only works on linux
        cmd = f"file -b {bin_path}"
        execute_res = execute_cmd(cmd)
        if execute_res['errcode'] == 0:
            bin_info = {
                'arch': '',
                'mode': '',
            }
            msg = execute_res['errmsg']
            if 'ARM' in msg:
                bin_info['arch'] = "ARM"
            elif 'PowerPC' in msg:
                bin_info['arch'] = "PPC"
            elif '386' in msg:
                bin_info['arch'] = "386"
            elif 'MIPS' in msg:
                bin_info['arch'] = 'MIPS'
            elif 'x86-64' in msg:
                bin_info['arch'] = "AMD64"
            if '64-bit' in msg:
                bin_info['mode'] = '64'
            elif '32-bit' in msg:
                bin_info['mode'] = '32'

            if bin_info['arch'] and bin_info['mode']:
                return {
                    'errcode': 0,
                    'bin_info': bin_info
                }
            else:
                return {
                    'errcode': 402,
                    'errmsg': f"can not get bin_info:{bin_info}"
                }
        return {
            'errcode': 401,
            'errmsg': f"Command execute failed:{execute_res['errmsg']}"
        }


def get_tags_by_repo(source_code_path, allow_versions=None, tag_pattern=None):
    """
    获取指定git仓库中所有tag（version）的版本，也可以用于对候选版本按照发布时间排序
    :param source_code_path:
    :param allow_versions: 仅返回指定版本特征
    :param tag_pattern: 指定tag的正则，去除一些不需要的版本
    :return:
    """
    git = Git(source_code_path)
    if tag_pattern:
        tags_with_date = sorted(
            [(str(tag), git.get_commit_from_tag(str(tag)).author_date) for tag in git.repo.tags if
             tag_pattern.match(str(tag))], key=lambda x: x[1])
    else:
        tags_with_date = sorted(
            [(str(tag), git.get_commit_from_tag(str(tag)).author_date) for tag in git.repo.tags],
            key=lambda x: x[1])
    ordered_tags = [tag_with_date[0] for tag_with_date in tags_with_date]
    if allow_versions:
        return [tag for tag in ordered_tags if tag in allow_versions]
    return ordered_tags


def get_md5(string: Union[str, Path]):
    """
    get md5 value of a given file path or a string
    :param string: str or path to a file
    :return: md5
    """
    if Path(string).is_file():
        with open(string, 'rb') as f:
            m = hashlib.md5()
            chunk = f.read(4096)
            while chunk:
                m.update(chunk)
                chunk = f.read(4096)
    else:
        m = hashlib.md5()
        m.update(string.encode())
    return m.hexdigest()
