from pathlib import Path

from mpire import WorkerPool
from tqdm import tqdm

from .tool_function import write_json


def generate_by_multi_bins(bin_paths, gen_method, process_num=1,):
    if process_num > 1:
        with WorkerPool(n_jobs=process_num) as pool:
            ext_results = pool.map_unordered(gen_method,
                                             bin_paths,
                                             progress_bar=True,
                                             progress_bar_options={'desc': f'gen {gen_method.__name__}'})

    else:
        success_num, fail_num = 0, 0
        ext_results = []
        bar = tqdm(bin_paths)
        for bin_path in bar:
            bin_path = Path(bin_path)
            res = gen_method(bin_path)
            if res['errcode'] == 0:
                success_num += 1
            else:
                fail_num += 1
            ext_results.append(res)
            bar.set_description(f"gen {gen_method.__name__}, {bin_path.name}, success:{success_num}, fail:{fail_num}")

    save_path = Path(f'results/{gen_method.__name__}_results.json')
    save_path.parent.mkdir(exist_ok=True)
    write_json(ext_results, save_path)
