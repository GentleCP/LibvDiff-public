#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from pathlib import Path

import torch

PLATFORM = sys.platform

if PLATFORM.startswith('linux'):
    IDA64_PATH = Path('/root/idapro-7.5/idat64')
    IDA_PATH = Path('/root/idapro-7.5/idat')
    IS_LINUX = True
elif PLATFORM.startswith('win'):
    IDA64_PATH = Path('D:/ida7.5/ida64.exe')
    IDA_PATH = Path('D:/ida7.5/ida.exe')
    IS_LINUX = False
else:
    raise ValueError(f'platform {PLATFORM} not support')

# if not IDA_PATH.exists() or not IDA64_PATH.exists():
#     raise FileNotFoundError('Can not find ida, please reset your ida path!')

DEVICE = torch.device('cuda:0') if torch.cuda.is_available() else torch.device('cpu')
SKIP_SUFFIX = {'.idb', '.idb64', '.id1', '.id0', '.id2', '.nam', '.til', '.i64', '.json', '.pkl', '.txt', '.py', '.csv'}

ROOT_PATH = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT_PATH.joinpath('saved/models/Asteria/crossarch_train_100000_1659022264.018625.pt')
MODEL_ARGS_PATH = ROOT_PATH.joinpath('saved/Asteria_args.pkl')

PASS_EXIST = False
