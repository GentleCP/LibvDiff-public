#!/usr/bin/python3
# -*- coding: utf-8 -*-
import numpy as np
from collections import Counter

def func_retrieval(bcsd_model, src_func, src_bin_feats, cand_funcs, tgt_bin_feats):
    try:
        src_embedding = src_bin_feats['embed_info'][src_func]['embedding']
    except (KeyError, TypeError):
        return []
    tgt_funcs = []
    tgt_embeddings = []
    for f in cand_funcs:
        try:
            embedding = tgt_bin_feats['embed_info'][f]['embedding'].reshape(-1)
        except (KeyError, TypeError):
            continue
        else:
            tgt_funcs.append(f)
            tgt_embeddings.append(embedding)
    tgt_embeddings = np.array(tgt_embeddings)
    try:
        simis = bcsd_model.get_simi_by_embedding(src_embedding, tgt_embeddings)
    except RuntimeError:
        return []
    simi_with_func = sorted([(f, simi) for f, simi in zip(tgt_funcs, simis)], key=lambda x: x[1], reverse=True)
    return simi_with_func


def get_cand_funcs_by_call_path(func, src_paths, tgt_paths, ):
    """
    :param func:
    :param src_paths: src_func -> (anchor, path_seq)
    :param tgt_paths: (anchor, path_seq) -> [func1, func2, ...]
    :return:
    """
    try:
        export_paths = src_paths[func]
    except KeyError:
        return set(), -1

    all_cand_funcs = []
    for export_path in export_paths:
        try:
            cand_funcs = tgt_paths[export_path]
        except KeyError:
            continue
        else:
            all_cand_funcs.extend(cand_funcs)

    key_times = set()
    ret_cand_funcs = set()
    counter = Counter(all_cand_funcs)
    for key, time_ in counter.most_common():
        key_times.add(time_)
        if len(key_times) > 1:
            break
        ret_cand_funcs.add(key)
    return ret_cand_funcs, counter.get(func, -1)


def check_version_by_constant_rvg(func_add, func_delete,
                                  str_add, str_delete,
                                  old_bin_feats,
                                  new_bin_feats,
                                  tgt_bin_feats):
    """"""
    rvg_old, rvg_new = 0, 0
    func_add_exports = func_add.intersection(set(new_bin_feats['exports']))
    func_add_other = func_add.difference(set(new_bin_feats['exports']))

    func_delete_exports = func_delete.intersection(set(old_bin_feats['exports']))
    func_delete_other = func_delete.difference(set(old_bin_feats['exports']))

    match_func_add_exports = tgt_bin_feats['exports'].intersection(func_add_exports)
    match_func_delete_exports = tgt_bin_feats['exports'].intersection(func_delete_exports)
    rvg_old += len(match_func_add_exports)
    rvg_new += len(match_func_delete_exports)

    match_str_add = tgt_bin_feats['strings'].intersection(str_add)
    match_str_delete = tgt_bin_feats['strings'].intersection(str_delete)
    rvg_old += len(match_str_add)
    rvg_new += len(match_str_delete)

    if rvg_old == 0 and rvg_new == 0 and not func_add_other and not func_delete_other:
        # no need for further comparison
        if func_add_exports or str_add:
            return {
                'rvg_old': 0,
                'rvg_new': 1,
                'msg': 'Can not match add features',
            }
        elif func_delete_exports or str_delete:
            return {
                'rvg_old': 1,
                'rvg_new': 0,
                'msg': 'Can not match delete features',
            }
    return {
        'rvg_old': rvg_old,
        'rvg_new': rvg_new,
        'msg': 'check by basic features'
    }


def get_cand_funcs(func, src_paths, tgt_bin_feats, tgt_paths, ap_on):
    if ap_on:
        try:
            all_cand_funcs, true_top_k = get_cand_funcs_by_call_path(func,
                                                                     src_paths,
                                                                     tgt_paths)
        except KeyError:
            all_cand_funcs = set(tgt_bin_feats['embed_info'].keys()).difference(tgt_bin_feats['exports'])
            true_top_k = -1
        return all_cand_funcs, true_top_k

    else:
        try:
            all_cand_funcs = set(tgt_bin_feats['embed_info'].keys()).difference(tgt_bin_feats['exports'])
        except AttributeError:
            return [], -1
        return all_cand_funcs, -1


def check_version_by_rvg2(func_add, func_delete, func_update, str_add, str_delete,
                          old_bin_feats, new_bin_feats, tgt_bin_feats,
                          ap_on=False, bcsd_threshold=0.95, bcsd_model=None, **kwargs):
    rvg_old, rvg_new = 0, 0

    try:
        func_add_exports = func_add.intersection(set(new_bin_feats['exports']))
        func_add_other = set([func for func in func_add.difference(set(new_bin_feats['exports'])) if
                    new_bin_feats['func2ast_depth'].get(func, 0) >= 10])
        func_delete_exports = func_delete.intersection(set(old_bin_feats['exports']))
        func_delete_other = set([func for func in func_delete.difference(set(old_bin_feats['exports'])) if
                       old_bin_feats['func2ast_depth'].get(func, 0) >= 10])
    except AttributeError:
        raise ValueError

    match_func_add_exports = tgt_bin_feats['exports'].intersection(func_add_exports)
    match_func_delete_exports = tgt_bin_feats['exports'].intersection(func_delete_exports)
    rvg_old += len(match_func_add_exports)
    rvg_new += len(match_func_delete_exports)

    match_str_add = tgt_bin_feats['strings'].intersection(str_add)
    match_str_delete = tgt_bin_feats['strings'].intersection(str_delete)
    rvg_old += len(match_str_add)
    rvg_new += len(match_str_delete)

    for func in func_add_other:
        all_cand_funcs, true_top_k = get_cand_funcs(func,
                                                    src_paths=new_bin_feats['anchor_path_node2eps'],
                                                    tgt_bin_feats=tgt_bin_feats,
                                                    tgt_paths=tgt_bin_feats['anchor_path_ep2nodes'],
                                                    ap_on=ap_on, )
        if not all_cand_funcs:
            continue
        simi_with_func = func_retrieval(bcsd_model=bcsd_model,
                                        src_func=func,
                                        src_bin_feats=new_bin_feats,
                                        cand_funcs=all_cand_funcs,
                                        tgt_bin_feats=tgt_bin_feats)

        if not simi_with_func:
            continue
        if simi_with_func[0][1] >= bcsd_threshold:
            rvg_old += 1
    if func_add_other and rvg_old == 0:
        return {
            'rvg_old': 0,
            'rvg_new': 1,
            'msg': 'add did not match'
        }
    for func in func_delete_other:
        all_cand_funcs, true_top_k = get_cand_funcs(func,
                                                    src_paths=old_bin_feats['anchor_path_node2eps'],
                                                    tgt_bin_feats=tgt_bin_feats,
                                                    tgt_paths=tgt_bin_feats['anchor_path_ep2nodes'],
                                                    ap_on=ap_on, )
        if not all_cand_funcs:
            continue
        simi_with_func = func_retrieval(bcsd_model=bcsd_model,
                                        src_func=func,
                                        src_bin_feats=old_bin_feats,
                                        cand_funcs=all_cand_funcs,
                                        tgt_bin_feats=tgt_bin_feats)
        if not simi_with_func:
            continue
        if simi_with_func[0][1] >= bcsd_threshold:
            rvg_new += 1

    # calculate update functions rvg
    matched_update = tgt_bin_feats['exports'].intersection(func_update)
    other_update = func_update.difference(matched_update)

    old_func_embeddings = []
    new_func_embeddings = []
    tgt_func_embeddings = []

    matched_update_exist = []
    for func in matched_update:
        try:
            old_embedding = old_bin_feats['embed_info'][func]['embedding'].reshape(-1)
            new_embedding = new_bin_feats['embed_info'][func]['embedding'].reshape(-1)
            tgt_embedding = tgt_bin_feats['embed_info'][func]['embedding'].reshape(-1)
        except (KeyError, AttributeError, TypeError):
            continue
        else:
            old_func_embeddings.append(old_embedding)
            new_func_embeddings.append(new_embedding)
            tgt_func_embeddings.append(tgt_embedding)
            matched_update_exist.append(func)

    embed_num = len(old_func_embeddings)

    if embed_num > 0:
        old_func_embeddings = np.array(old_func_embeddings)
        new_func_embeddings = np.array(new_func_embeddings)
        tgt_func_embeddings = np.array(tgt_func_embeddings)
        old_simis = bcsd_model.get_simi_by_embedding(old_func_embeddings, tgt_func_embeddings)
        new_simis = bcsd_model.get_simi_by_embedding(new_func_embeddings, tgt_func_embeddings)
        old_simi = old_simis.sum()
        new_simi = new_simis.sum()
        rvg_old += embed_num - old_simi
        rvg_new += embed_num - new_simi

    other_update_simi_old = 0
    other_update_simi_new = 0

    true_top_k_max = -1
    for func in other_update:
        all_cand_funcs, true_top_k = get_cand_funcs(func,
                                                    src_paths=old_bin_feats['anchor_path_node2eps'],
                                                    tgt_bin_feats=tgt_bin_feats,
                                                    tgt_paths=tgt_bin_feats['anchor_path_ep2nodes'],
                                                    ap_on=ap_on, )
        if true_top_k > true_top_k_max:
            true_top_k_max = true_top_k
        if not all_cand_funcs:
            continue

        simi_with_func = func_retrieval(bcsd_model=bcsd_model,
                                        src_func=func,
                                        src_bin_feats=old_bin_feats,
                                        cand_funcs=all_cand_funcs,
                                        tgt_bin_feats=tgt_bin_feats)
        if simi_with_func:
            func_from_old = simi_with_func[0]
        else:
            continue
        all_cand_funcs, true_top_k = get_cand_funcs(func,
                                                    src_paths=new_bin_feats['anchor_path_node2eps'],
                                                    tgt_bin_feats=tgt_bin_feats,
                                                    tgt_paths=tgt_bin_feats['anchor_path_ep2nodes'],
                                                    ap_on=ap_on, )
        if true_top_k > true_top_k_max:
            true_top_k_max = true_top_k
        if not all_cand_funcs:
            continue
        simi_with_func = func_retrieval(bcsd_model=bcsd_model,
                                        src_func=func,
                                        src_bin_feats=new_bin_feats,
                                        cand_funcs=all_cand_funcs,
                                        tgt_bin_feats=tgt_bin_feats)
        if simi_with_func:
            func_from_new = simi_with_func[0]
        else:
            continue

        if func_from_old[1] > bcsd_threshold or func_from_new[1] > bcsd_threshold:
            rvg_old += 1 - func_from_old[1]
            rvg_new += 1 - func_from_new[1]
            other_update_simi_old += func_from_old[1]
            other_update_simi_new += func_from_new[1]

    return {
        'rvg_old': rvg_old,
        'rvg_new': rvg_new,
        'msg': 'RVG'
    }


def version_range_locating(vc_x, vc_y, vct, threshold=0.2):
    s_vct_old = vct['vc_x']
    s_vct_new = vct['vc_y']

    try:
        version_range_by_vc_x = set(
            s_vct_old.loc[s_vct_old.apply(lambda x: (abs(x - vc_x)) / vc_x <= threshold)].index)
    except ZeroDivisionError:
        version_range_by_vc_x = set(s_vct_old[s_vct_old == vc_x].index)

    try:
        version_range_by_vc_y = set(
            s_vct_new.loc[s_vct_new.apply(lambda x: (abs(x - vc_y)) / vc_y <= threshold)].index)
    except ZeroDivisionError:
        version_range_by_vc_y = set(s_vct_new[s_vct_new == vc_y].index)
    return version_range_by_vc_x.intersection(version_range_by_vc_y)
