#!/usr/bin/python3
# -*- coding: utf-8 -*-
import time
import warnings

import sys
from argparse import ArgumentParser

sys.path.append('data_process')
warnings.filterwarnings('ignore')
from pathlib import Path
from tqdm import tqdm
from collections import defaultdict

import pandas as pd

from data_process.vct_generator import VCTGenerator
from data_process.utils.data_prepare import load_bin_features
from data_process.utils.tool_function import read_json
from data_process.feat_encoding import load_model

from version_identifier import check_version_by_constant_rvg, check_version_by_rvg2, version_range_locating

DATASET_PATH = Path('data_process/dataset/')
FEATURE_PATH = Path('data_process/features')

OSS2LIB = {
    'aws-c-common': 'libaws-c-common',
    'c-blosc': 'libblosc',
    'expat': 'libexpat',
    'freetype': 'libfreetype',
    'mbedtls': 'libmbedcrypto',
    'libpng': 'libpng',
    'libxml2': 'libxml2',
    'zlib': 'libz',
    'openssl': 'libcrypto',
}

SAVE_DIR = Path('saved/libvdiff_idf_all_res')
SAVE_DIR.mkdir(exist_ok=True, parents=True)

ALL_OPT = ['O0', 'O1', 'O2', 'O3']
ALL_ARCH = ['ARM', 'X86', 'PPC', 'X64']


def prepare_cross_optim_features(oss, lib, arch, versions=None):
    option2ver2bin_feats = defaultdict(dict)

    for opt in ALL_OPT:
        prj_path = DATASET_PATH.joinpath(f'{oss}/{lib}/{arch}/{opt}/')
        for version_path in prj_path.iterdir():
            if version_path.name.startswith('.'):
                continue
            if versions and version_path.name not in versions:
                continue
            option2ver2bin_feats[f"{arch}-{opt}"][version_path.name] = load_bin_features(version_path)
    return option2ver2bin_feats


def prepare_cross_arch_features(oss, lib, opt, versions=None):
    option2ver2bin_feats = defaultdict(dict)

    for arch in ALL_ARCH:
        prj_path = DATASET_PATH.joinpath(f'{oss}/{lib}/{arch}/{opt}/')
        for version_path in prj_path.iterdir():
            if version_path.name.startswith('.'):
                continue
            if versions and version_path.name not in versions:
                continue
            option2ver2bin_feats[f"{arch}-{opt}"][version_path.name] = load_bin_features(version_path)
    return option2ver2bin_feats


def prepare_cross_both_features(oss, lib, versions=None):
    option2ver2bin_feats = defaultdict(dict)

    for option in ['ARM-O2', 'X86-O0', 'X86-O1', 'X86-O3', 'X64-O0', 'X64-O1', 'X64-O3', 'PPC-O0', 'PPC-O1',
                   'PPC-O3']:
        arch, opt = option.split('-')
        prj_path = DATASET_PATH.joinpath(f'{oss}/{lib}/{arch}/{opt}/')
        for version_path in prj_path.iterdir():
            if version_path.name.startswith('.'):
                continue
            if versions and version_path.name not in versions:
                continue
            option2ver2bin_feats[f"{arch}-{opt}"][version_path.name] = load_bin_features(version_path)
    return option2ver2bin_feats


def load_vd(oss, lib):
    vd_func_path = FEATURE_PATH.joinpath(f"{oss}/version-diff/vp_diffs-func-{lib}.json")
    vd_str_path = FEATURE_PATH.joinpath(f"{oss}/version-diff/vp_diffs-str-{lib}.json")
    try:
        func_diffs = read_json(vd_func_path)
    except FileNotFoundError:
        print(f'[-] warning! can not find func diffs of {oss}-{lib}')
        func_diffs = {}
    try:
        str_diffs = read_json(vd_str_path)
    except FileNotFoundError:
        print(f'[-] warning! can not find func diffs of {oss}-{lib}')
        str_diffs = {}
    return func_diffs, str_diffs


def prepare_features_and_options(versions, oss, lib, exp):
    if exp == "cross_optim":
        arch = "ARM"
        option2ver2bin_feats = prepare_cross_optim_features(oss=oss, lib=lib, arch=arch, versions=versions)
        all_options = []
        for base_opt in ALL_OPT:
            for pred_opt in ALL_OPT:
                if base_opt == pred_opt:
                    continue
                all_options.append((f"{arch}-{base_opt}", f"{arch}-{pred_opt}"))
    elif exp == "cross_arch":
        opt = "O2"
        option2ver2bin_feats = prepare_cross_arch_features(oss=oss, lib=lib, opt=opt, versions=versions)
        all_options = []
        for base_arch in ALL_ARCH:
            for pred_arch in ALL_ARCH:
                if base_arch == pred_arch:
                    continue
                all_options.append((f"{base_arch}-{opt}", f"{pred_arch}-{opt}"))

    else:
        option2ver2bin_feats = prepare_cross_both_features(oss=oss, lib=lib, versions=versions)
        all_options = [('ARM-O2', 'X86-O0'), ('ARM-O2', 'X86-O1'), ('ARM-O2', 'X86-O3'),
                       ('ARM-O2', 'X64-O0'), ('ARM-O2', 'X64-O1'), ('ARM-O2', 'X64-O3'),
                       ('ARM-O2', 'PPC-O0'), ('ARM-O2', 'PPC-O1'), ('ARM-O2', 'PPC-O3'), ]
    return option2ver2bin_feats, all_options


def main(oss, cvf, apf, exp):
    lib = OSS2LIB[oss]
    Asteria = load_model()
    print(f"oss:{oss}, lib: {lib}, cvf: {cvf}, apf: {apf}, exp:{exp}")
    sorted_versions = read_json(FEATURE_PATH.joinpath(f"{oss}/sorted_versions.json"))
    option2ver2bin_feats, all_options = prepare_features_and_options(sorted_versions, oss, lib, exp)
    all_vd_func, all_vd_str = load_vd(oss=oss, lib=lib)
    try:
        df_vct = pd.read_csv(f'data_process/features/{oss}/version-diff/vct-{lib}.csv', index_col=0)
    except FileNotFoundError:
        print(f'[-] warning can not find vct of {oss}-{lib}')
        df_vct = None

    # sorted_versions = sorted(list(allow_versions))
    idf_datas = []
    true_num = 0
    total_num = 0
    func_add_max, func_delete_max, _ = all_vd_func[f"{sorted_versions[0]}@{sorted_versions[-1]}"]
    for base_option, pred_option in all_options:
        bar = tqdm(sorted_versions)
        for true_version in bar:
            start = time.time()

            if cvf and df_vct is not None:
                vc_x, vc_y = VCTGenerator.calculate_vc(
                    vd_add=func_add_max,
                    vd_delete=func_delete_max,
                    tgt_exports=option2ver2bin_feats[pred_option][true_version]['exports']
                )
                tmp_versions = version_range_locating(vc_x=vc_x, vc_y=vc_y, vct=df_vct)
                cand_versions = [version for version in sorted_versions if version in tmp_versions]
                if len(cand_versions) == 0:
                    cand_versions = sorted_versions
                pred_versions = [cand_versions[0]]
                for cur_version in cand_versions[1:]:
                    func_add, func_delete, func_update = all_vd_func.get(f"{pred_versions[-1]}@{cur_version}",
                                                                         ([], [], []))
                    try:
                        str_add, str_delete, _ = all_vd_str.get(f"{pred_versions[-1]}@{cur_version}", ([], [], []))
                    except ValueError:
                        str_add, str_delete = all_vd_str.get(f"{pred_versions[-1]}@{cur_version}", ([], [],))

                    res = check_version_by_constant_rvg(func_add=set(func_add),
                                                        func_delete=set(func_delete),
                                                        str_add=set(str_add),
                                                        str_delete=set(str_delete),
                                                        old_bin_feats=option2ver2bin_feats[base_option][
                                                            pred_versions[-1]],
                                                        new_bin_feats=option2ver2bin_feats[base_option][cur_version],
                                                        tgt_bin_feats=option2ver2bin_feats[pred_option][true_version])
                    if res['rvg_old'] > res['rvg_new']:
                        pred_versions = [cur_version]
                    elif res['rvg_old'] == res['rvg_new']:
                        pred_versions.append(cur_version)

            else:
                pred_versions = sorted_versions

            pred_version = pred_versions[0]

            for cur_version in pred_versions[1:]:
                func_add, func_delete, func_update = all_vd_func.get(f"{pred_version}@{cur_version}",
                                                                     ([], [], []))
                try:
                    str_add, str_delete, _ = all_vd_str.get(f"{pred_version}@{cur_version}", ([], [], []))
                except ValueError:
                    str_add, str_delete = all_vd_str.get(f"{pred_version}@{cur_version}", ([], [],))
                old_bin_feats = option2ver2bin_feats[base_option][pred_version]
                new_bin_feats = option2ver2bin_feats[base_option][cur_version]

                res = check_version_by_rvg2(func_add=set(func_add),
                                            func_delete=set(func_delete),
                                            func_update=set(func_update),
                                            str_add=set(str_add),
                                            str_delete=set(str_delete),
                                            old_bin_feats=old_bin_feats,
                                            new_bin_feats=new_bin_feats,
                                            tgt_bin_feats=option2ver2bin_feats[pred_option][true_version],
                                            ap_on=apf,
                                            bcsd_model=Asteria
                                            )
                if res['rvg_old'] > res['rvg_new']:
                    pred_version = cur_version

            time_cost = time.time() - start
            if pred_version == true_version:
                print(f'\n[+] source bin option {base_option}, target bin option: {pred_option}, true: {true_version}, predict: {pred_version}')
                true_num += 1
            else:
                print(f'\n[-] source bin option {base_option}, target bin option: {pred_option}, true: {true_version}, predict: {pred_version}')
            total_num += 1
            bar.set_description(
                f'identify {true_version}-{base_option} is {pred_version}-{pred_option}, {true_num / total_num:.3f}')

            idf_datas.append(
                (base_option, pred_option, true_version, pred_version, true_version == pred_version, time_cost))

    df_idf_res = pd.DataFrame(idf_datas, columns=['base_option', 'pred_option', 'true_version', 'pred_version',
                                                  'is_true', 'time_cost'])
    save_name_prefix = f"{exp}@{oss}_{lib}"

    if apf and cvf:
        save_name_prefix += f"@apf@cvf"
    elif apf and not cvf:
        save_name_prefix += f"@apf@no_cvf"
    elif not apf and cvf:
        save_name_prefix += f"@no_apf@cvf"
    else:
        save_name_prefix += f"@no_apf@no_cvf"

    df_idf_res.to_csv(f'{SAVE_DIR}/{save_name_prefix}@idf_res.csv', index=False)

    print(f'Finished, precision:{true_num / total_num:.3f}')


if __name__ == '__main__':
    parser = ArgumentParser()
    CVF_ON = None
    AP_ON = None
    exp_mapping = {
        'co': 'cross_optim',
        'ca': 'cross_arch',
        'cb': 'cross_both'
    }

    parser.add_argument('-o', '--oss', default='freetype', help='specify OSS to test')
    parser.add_argument('-c', '--cvf', action='store_true', help='Turn on cvf')
    parser.add_argument('-a', '--apf', action='store_true', help='Turn on apf')
    parser.add_argument('-e', '--exp', default='co',
                        help='Experiment (co: cross optimization, ca: cross architecture, cb: cross both)')

    args = parser.parse_args()
    if CVF_ON is not None:
        args.cvf = CVF_ON
    if AP_ON is not None:
        args.apf = AP_ON

    main(oss=args.oss, cvf=args.cvf, apf=args.apf, exp=exp_mapping[args.exp])
