#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Utilize BCSD model to encode asteria features
"""
import time
from pathlib import Path
import torch
import argparse
from tqdm import tqdm
from cptools import LogHandler

from settings import DEVICE, MODEL_PATH, MODEL_ARGS_PATH
from utils.similarity import AsteriaCalculator
from utils.tool_function import read_pickle, write_pickle


def load_model(device=DEVICE):
    print(f'load model from {MODEL_PATH}, device is {DEVICE}')
    args = read_pickle(MODEL_ARGS_PATH)
    args.resume = MODEL_PATH
    return AsteriaCalculator(config=args, device=device)


class FeatEncoder(object):

    def __init__(self, cuda_id=1):
        """
        load model
        :param process_num: maximum to the number of your GPUs
        :return:
        """
        self.logger = LogHandler('FeatEncoder')
        self.model_calculators = load_model(device=torch.device(f'cuda:{cuda_id}'))

    @staticmethod
    def encode_asteria_feature(asteria, feat_path, encode_path):
        """
        Embed asteria features into vectors
        :param asteria:
        :param feat_path:
        :param encode_path:
        :return:
        """
        func2embed_info = {}
        res = {
            'feat_path': str(feat_path),
            'embed_path': str(encode_path)
        }
        if encode_path.exists():
            return {
                'errcode': 0,
                'errmsg': 'exist'
            }
        try:
            for func_name, func_info in tqdm(read_pickle(feat_path).items(), desc=f'encoding ast <{asteria.device}>'):
                ast = func_info['ast']
                start = time.time()
                with torch.no_grad():
                    embed = asteria.func_embedding(ast)
                func2embed_info[func_name] = {
                    'ea': func_info['ea'],
                    'embedding': embed,
                    'feat_time_cost': func_info.get('time_cost', None),
                    'time_cost': time.time() - start
                }
        except EOFError:
            res.update({
                'errcode': 400,
                'errmsg': 'Asteria feature is empty',
            })
        except FileNotFoundError:
            res.update({
                'errcode': 404,
                'errmsg': 'can not find feature path, please generate it first',
            })
        else:
            res.update({
                'errcode': 0,
            })
            write_pickle(func2embed_info, encode_path)
        return res

    def encode_by_multi_bins(self, bin_paths):
        asteria = self.model_calculators
        success_num, fail_num = 0, 0
        ext_results = []
        bar = tqdm(bin_paths)
        for bin_path in bar:
            bin_path = Path(bin_path)
            feat_path = bin_path.parent.joinpath(f"Asteria_features.pkl")
            embedding_path = bin_path.parent.joinpath(f'Asteria_embeddings.pkl')
            res = self.encode_asteria_feature(asteria, feat_path, embedding_path)
            if res['errcode'] == 0:
                success_num += 1
            else:
                fail_num += 1
            ext_results.append(res)
            bar.set_description(
                f"gen {self.encode_asteria_feature.__name__}, {bin_path.name}, success:{success_num}, fail:{fail_num}")

    def run(self, bin_paths):
        self.logger.info('Encoding start')
        self.encode_by_multi_bins(bin_paths)
        self.logger.info('Encoding finished')


from feature_generator import load_bin_paths


def main():
    # If your computer has multiple GPUs, they can be utilized to encode functions in parallel.
    # For example, suppose there are 4 binary paths and 2 GPUs, you can embed them with two GPUs as follows
    # python feat_encoding.py -i 0 -l 0 -r 2 and python feat_encoding.py -i 1 -l 2
    args = argparse.ArgumentParser()
    args.add_argument('-o', '--oss', default='freetype', help='oss')
    args.add_argument('-i', '--cuda_id', default=0, help='cuda id')
    args.add_argument('-l', '--left', default=0, help='The left index of binary paths')
    args.add_argument('-r', '--right', default=-1, help='The right index of binary paths')
    arg = args.parse_args()
    feat_encoder = FeatEncoder(cuda_id=arg.cuda_id)
    bin_paths = load_bin_paths(oss=arg.oss)
    left_index = int(arg.left)
    right_index = int(arg.right) if int(arg.right) > 0 else len(bin_paths) + 1
    feat_encoder.run(bin_paths[left_index:right_index])


if __name__ == '__main__':
    main()
