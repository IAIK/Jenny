#!/usr/bin/env python3
from collections import OrderedDict
import sys
import numpy as np
import matplotlib.pyplot as plt
import tikzplotlib
from matplotlib.ticker import MultipleLocator, FormatStrFormatter, AutoMinorLocator, StrMethodFormatter, NullFormatter
import pandas as pd
from pprint import pprint
from scipy import stats
from plot_common import *
from os.path import splitext

#-------------------------------------------------------------------------------
# set plot font similar to latex
rcparamsstuff()
font_small = 11
#-------------------------------------------------------------------------------

def get_all_values(results_csvs, mhz):
    data = []
    for f in results_csvs:
        data.append(pd.read_csv(f,sep=";",comment="#"))
    data = pd.concat(data, axis=0)

    datadict = {}
    datadict["data"] = data
    groups = data.groupby(["mechanism", "filter"])
    groups = groups.apply(lambda g: g[g["overall"] <= g["overall"].quantile(0.99)])
    groups = groups.reset_index(drop=True).groupby(["mechanism", "filter"])

    datadict["groups"] = groups
    datadict["median"] = groups.median()
    datadict["mean"] = groups.mean()
    datadict["std"] = groups.std()
    datadict["min"] = groups.min()
    datadict["max"] = groups.max()
    datadict["mhz"] = float(mhz)

    return datadict
#-------------------------------------------------------------------------------

mechanisms = mechanisms_to_dict([
    "nul", 
    "none", 
    #"ptrace", 
    "ptrace_delegate", 
    #"seccomp_user", 
    "sysmodule", 
    "indirect",
    ])

paper = False
subtract_baseline = False

if __name__ == "__main__":
    src_file = sys.argv[1]
    if len(sys.argv) > 2:
        assert sys.argv[1] == "paper"
        src_file = sys.argv[2]
        paper = True
    dst_file = splitext(src_file)[0] + "_initialization_overhead.pdf"

    testcase_name = None
    with open(src_file) as f:
        line = f.readline()
        testcase_name = line[2:-1]

    data = get_all_values([src_file], 0)
    data["mean"] /= 1.0e3
    data["std"] /= 1.0e3
    unit = "ms"

    groups = set([g for g in data["groups"].groups])

    baseline_mean = 0
    baseline_std  = 0
    if subtract_baseline:
        baseline_mean = (data["mean"].loc["nul"].loc["nul"][1]) # there is only a overall timing
        baseline_std  = (data["std"].loc["nul"].loc["nul"][1])
        del mechanisms["nul"]

    def get_field(field, mechanism, filt):
        return data[field].loc[mechanism].loc[filt][1] - data[field].loc[mechanism].loc[filt][0]

    def data_get_mean(filt):
        results = []
        for mechanism in mechanisms.keys():
            filt_tmp = "nul" if mechanism == "nul" and filt == "none" else filt # "nul" mechanism has no "none" filter. it's called "nul"
            if (mechanism, filt_tmp) in groups:
                results.append(get_field("mean", mechanism, filt_tmp) - baseline_mean)
            else:
                results.append(0)
        return results

    def data_get_std(filt):
        results = []
        for mechanism in mechanisms.keys():
            if (mechanism, filt) in groups:
                results.append(get_field("std", mechanism, filt) + baseline_std)
            else:
                results.append(0)
        return results

    def data_to_error(filt):
        return np.asarray(data_get_std(filt))

    filtersets = filtersets_to_dict([
        "none",
        "self-donky",
        "self-mpk",
        "localstorage",
    ])

    # get data
    data_processed = {}
    data_processed["values"] = {}
    data_processed["error"] = {}
    for filterset in filtersets.keys():
        data_processed["values"][filterset] = data_get_mean(filterset)
        data_processed["error"][filterset] = data_to_error(filterset)

    rcParams["figure.figsize"] = 6.5,4
    rcParams['font.size'] = 12

    x = np.arange(len(mechanisms)).astype(np.float32)  # the label locations
    width = 0.15  # the width of the bars
    fig, ax = plt.subplots()

    args = {"edgecolor":"Black", "capsize":3}
    for index,(filter,filter_data) in enumerate(filtersets.items()):
        width2 = (len(filtersets) + (len(filtersets) % 2)) / 2
        yerr = data_processed["error"][filter]
        filter_data["rects"] = ax.bar(x + (0.5 - width2 + index) * width, data_processed["values"][filter], width, yerr=yerr, **args, color=filter_data["color"], label=filter_data["label"])
        autolabel(filter_data["rects"], ax, yerr=yerr, size=font_small)#, fmt="{:.2f} ms")

    # lines:
    filter_none_values = data_processed["values"]["none"]
    ax.axhline(y = filter_none_values[list(mechanisms.keys()).index("none")], color="black", linestyle="--", linewidth=1)
    if not subtract_baseline:
        ax.axhline(y = filter_none_values[list(mechanisms.keys()).index("nul")], color="black", linestyle="--", linewidth=1)
    
    plt.xticks(range(len(mechanisms)), mechanisms.values()) # , rotation="60", horizontalalignment="right"
    print(src_file)
    ax.legend(
        frameon=False,
        borderpad=0.4, # default borderpad=0.4
        loc="upper right",
        ncol=1
    )
    ax.margins(y=0.4)

    if subtract_baseline:
        plt.ylabel("Overhead [{}]".format(unit))
    else:
        plt.ylabel("Total runtime [{}]".format(unit))

    plt.tight_layout()
    plt.savefig(dst_file, bbox_inches="tight", pad_inches=0)

    print(dst_file)

    plt.close()
#-------------------------------------------------------------------------------
