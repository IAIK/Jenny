#!/usr/bin/env python3
from collections import OrderedDict
import sys
import numpy as np
import matplotlib.pyplot as plt
import tikzplotlib
from matplotlib.ticker import MultipleLocator, FormatStrFormatter, AutoMinorLocator, StrMethodFormatter, NullFormatter
import pandas as pd
#from pylab import rcParams
from plot_common import *
from os.path import splitext
from termcolor import colored
from pprint import pprint

#-------------------------------------------------------------------------------
# set plot font similar to latex
rcparamsstuff()
font_small = 13
#-------------------------------------------------------------------------------

def get_all_values(results_csvs, mhz):
    data = []
    for f in results_csvs:
        df = pd.read_csv(f,sep=";",comment="#",usecols=['mechanism','filter','value'])
        data.append(df)
    data = pd.concat(data, axis=0)

    num_samples_pre_filtering = 0
    num_samples_post_filtering = 0

    datadict = {}
    datadict["data"] = data
    groups = data.groupby(["mechanism", "filter"])

    # pre-filter stats
    num_samples_pre_filtering = len(data.index)
    groups_copy = data.groupby(["mechanism", "filter"])
    datadict["pre_filter_median"] = groups_copy.median()
    datadict["pre_filter_mean"]   = groups_copy.mean()
    datadict["pre_filter_std"]    = groups_copy.std()
    datadict["pre_filter_min"]    = groups_copy.min()
    datadict["pre_filter_max"]    = groups_copy.max()

    # remove outlier
    groups = groups.apply(lambda g: g[ g["value"] <= g["value"].median()*2 ])

    groups = groups.reset_index(drop=True).groupby(["mechanism", "filter"])
    num_samples_post_filtering = sum((x for x in groups.size()))

    datadict["groups"] = groups
    datadict["median"] = groups.median()
    datadict["mean"] = groups.mean()
    datadict["std"] = groups.std()
    datadict["min"] = groups.min()
    datadict["max"] = groups.max()
    datadict["mhz"] = float(mhz)
    datadict["num_samples_pre_filtering"] = num_samples_pre_filtering
    datadict["num_samples_post_filtering"] = num_samples_post_filtering

    return datadict

#-------------------------------------------------------------------------------
paper = False
if __name__ == "__main__":
    src_file = sys.argv[1]
    if len(sys.argv) > 2:
        assert sys.argv[1] == "paper"
        src_file = sys.argv[2]
        paper = True
    dst_file = splitext(src_file)[0]
    print(src_file)

    mechanisms = mechanisms_to_dict([
        #"ptrace", 
        "ptrace_delegate", 
        #"seccomp_user", 
        "sysmodule", 
        "indirect",
    ], paper)

    if "output_true.csv" in src_file:
        print(colored("Skipping true, because values only exist for plotting initialization overhead", 'red'))
        exit(0)

    testcase_name = None
    with open(src_file) as f:
        line = f.readline()
        testcase_name = line[2:-1]

    data = get_all_values([src_file], 0)

    groups = set([g for g in data["groups"].groups])
    
    def get_field(field, mechanism, filt):
        try:
            return int(data[field].loc[mechanism].loc[filt][0])
        except:
            print(colored("Warning: missing {}/{}/{}".format(field, mechanism, filt), 'red'))
            return 0
    
    def get_mean(mechanism, filt):
        return get_field("mean", mechanism, filt)

    def get_std(mechanism, filt):
        return get_field("std", mechanism, filt)

    def data_get_field(field, filt):
        results = []
        for mechanism in mechanisms.keys():
            if (mechanism, filt) in groups:
                results.append(get_field(field, mechanism, filt))
            else:
                results.append(0)
        return results

    baseline_mean = get_mean("none", "none")
    baseline_std = get_std("none", "none")

    def data_to_normalized_mean(filt):
        return [val / baseline_mean for val in data_get_field("mean", filt)]

    def data_to_error(filt):
        means              = np.asarray(data_get_field("mean", filt))
        raw_errors         = np.asarray(data_get_field("std", filt))
        errors = compute_ratio_std(baseline_mean, baseline_std, means, raw_errors)
        return errors

    def zero_to_none(array):
        return [None if item == 0 else item for item in array]

    filtersets = filtersets_to_dict([
        "none",
        "self-donky",
        "self-mpk",
        "localstorage",
    ])

    data_processed = {}
    data_processed["values"] = {}
    data_processed["error"] = {}

    for filterset in filtersets.keys():
        data_processed["values"][filterset] = data_to_normalized_mean(filterset)
        data_processed["error"][filterset] = data_to_error(filterset)

    # summary: 
    data_summary = {}
    data_summary["mechanism"] = [x.replace("\n", "\\\\") for x in mechanisms.values()]
    for filterset in filtersets.keys():
        data_summary[filterset] = zero_to_none(data_processed["values"][filterset]);
    pd.DataFrame(
        data_summary
    ).to_csv(dst_file + ".summary", na_rep="nan", float_format="%.2f", sep=";", index=False)

    print_stats_datadicts([[data]])

    if paper:
        rcParams["figure.figsize"] = 6,4
    else:
        font_small = 11
        rcParams["figure.figsize"] = 6,5
        rcParams["font.size"] = 12

    x = np.arange(len(mechanisms)).astype(np.float32)  # the label locations
    #width = 0.15  # the width of the bars
    width = 1/len(filtersets) * 0.9
    fig, ax = plt.subplots()

    # plot
    args = {"edgecolor":"Black", "capsize":3}
    for index,(filter,filter_data) in enumerate(filtersets.items()):
        width2 = (len(filtersets) + (len(filtersets) % 2)) / 2
        yerr = data_processed["error"][filter]
        filter_data["rects"] = ax.bar(x + (0.5 - width2 + index) * width, data_processed["values"][filter], width, yerr=yerr, **args, color=filter_data["color"], label=filter_data["label"])
        autolabel(filter_data["rects"], ax, yerr=yerr, size=font_small)

    if paper:
        plt.xticks(range(len(mechanisms)), mechanisms.values()) # , rotation="60", horizontalalignment="right"
        print(src_file)
        if "output_dd.csv" in src_file: # or True:
            ax.legend(
                frameon=False,
                borderpad=0.4, # default borderpad=0.4
                loc="upper right",
                ncol=1
            )
        ax.margins(y=0.18)

        axes = plt.gca()
        axes.set_ylim([0,5])

    else:
        plt.xticks(range(len(mechanisms)), mechanisms.values())
        ax.legend(
            frameon=False,
            borderpad=0.4, # default borderpad=0.4
            loc="upper left",
            ncol=2
        )
        ax.margins(y=0.5)

    plt.tight_layout()
    plt.savefig(dst_file + ".pdf", bbox_inches="tight", pad_inches=0)

    print(dst_file + ".pdf")

    plt.close()
#-------------------------------------------------------------------------------
