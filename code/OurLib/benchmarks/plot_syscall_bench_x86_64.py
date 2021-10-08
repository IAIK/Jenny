#!/usr/bin/env python3
from collections import OrderedDict
from pprint import pprint
import sys
import numpy as np
import matplotlib.pyplot as plt
import tikzplotlib
from matplotlib.ticker import MultipleLocator, FormatStrFormatter, AutoMinorLocator, StrMethodFormatter, NullFormatter
import pandas as pd
#from pylab import rcParams
import math
import matplotlib
from plot_common import *
import datetime
import os
import copy

#-------------------------------------------------------------------------------
# set plot font similar to latex
rcparamsstuff()
font_small = 10
#-------------------------------------------------------------------------------

def get_all_values(results_csvs, mhz):
    data = []
    for f in results_csvs:
        data.append(pd.read_csv(f,sep=";"))#,dtype={2:np.float64}
    data = pd.concat(data, axis=0)

    num_samples_pre_filtering = 0
    num_samples_post_filtering = 0

    datadict = {}
    datadict["data"] = data
    groups = data.groupby(["syscall"])

    # pre-filter stats
    num_samples_pre_filtering = len(data.index)
    groups_copy = data.groupby(["syscall"])
    datadict["pre_filter_median"] = groups_copy.median()
    datadict["pre_filter_mean"]   = groups_copy.mean()
    datadict["pre_filter_std"]    = groups_copy.std()
    datadict["pre_filter_min"]    = groups_copy.min()
    datadict["pre_filter_max"]    = groups_copy.max()

    # remove outlier
    #groups = groups.apply(lambda group: group[group["time"] <= group["time"].quantile(0.99)])
    groups = groups.apply(lambda group: group[ group["time"] <= group["time"].median()*2 ])

    groups = groups.reset_index(drop=True).groupby(["syscall"])
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
platform = sys.argv[1]
input_dir = sys.argv[2]
output_dir = sys.argv[3]
if len(sys.argv) > 4:
    paper = True

#-------------------------------------------------------------------------------
filtersets = filtersets_to_dict([
    "none",
    "self-donky",
    "self-mpk",
    "localstorage",
])
filtersets["just-domain"] = None
filtersets["old-extended-domain"] = None

filtersets_getpid = OrderedDict([
        ("none",                {"color":lighten_color("White",   0.3),  "label":"None",        }),
        ("self-donky",          {"color":lighten_color("Cyan",    0.3),  "label":"monitor filter",        }),
        ("old-extended-domain", {"color":lighten_color("Black",   0.3),  "label":"monitor + domain filter",   }),
    ])
#-------------------------------------------------------------------------------
mechanisms = mechanisms_to_dict([
    "none",  # note: first must be "none" since we use mechanisms[1:] later on
    "ptrace", 
    "ptrace_delegate", 
    "seccomp_user", 
    "sysmodule", 
    "indirect",
    ], paper)
#-------------------------------------------------------------------------------
all_data = {}
for mechanism in mechanisms.keys():
    all_data[mechanism] = {}
    for filterset in filtersets.keys():
        val = None
        path = input_dir + "/results_" + platform + "_"+mechanism+"_"+filterset+".csv"
        try:
            val = get_all_values([path], 0)
        except Exception as e:
            print("Skipping {}: ".format(path))
            #print(e)
            pass
        all_data[mechanism][filterset] = val

data_per_filterset = {}
for filterset in filtersets.keys():
    data_per_filterset[filterset] = {}
    arr = [ all_data[mechanism][filterset] for mechanism in mechanisms.keys() ]
    data_per_filterset[filterset][mechanism] = arr
#-------------------------------------------------------------------------------

def plot(test_name):
    global font_small
    def get_mean(data):
        # note: using test_name from current scope
        return np.float64(data["mean"].loc[test_name])
    def get_std_raw(data):
        # note: using test_name from current scope
        return np.float64(data["std"].loc[test_name])

    def normalized_means(data):
        baseline = get_mean(all_data["none"]["none"])
        return [get_mean(x) / baseline if x else 0 for x in data]

    def data_to_error(data):
        baseline_value_med = np.asarray([get_mean(all_data["none"]["none"])      for x in data])
        baseline_error_raw = np.asarray([get_std_raw(all_data["none"]["none"])   for x in data])
        means              = np.asarray([get_mean(x)     if x else 0.0 for x in data])
        raw_errors         = np.asarray([get_std_raw(x)  if x else 0.0 for x in data])
        errors = compute_ratio_std(baseline_value_med, baseline_error_raw, means, raw_errors)
        return errors

    def zero_to_none(array):
        return [None if item == 0 else item for item in array]

    data_processed = {}
    data_processed["values"] = {}
    data_processed["error"] = {}
    for filterset in filtersets.keys():
        d = data_per_filterset[filterset][mechanism]
        #if not d:
        #    continue
        data_processed["values"][filterset] = normalized_means(d)
        data_processed["error"][filterset] = data_to_error(d)

    # summary: 
    output_file = output_dir + "/tc_" + test_name
    data_summary = {}
    data_summary["mechanism"] = [x.replace("\n", "\\\\") for x in mechanisms.values()]
    for filterset in filtersets.keys():
        data_summary[filterset] = zero_to_none(data_processed["values"][filterset]);
    pd.DataFrame(data_summary).to_csv(output_file + ".csv", na_rep="nan", float_format="%.2f", sep=";", index=False)

    rcParams["figure.figsize"] = 6,2.2

    filtersets_to_plot = {key: value for key, value in filtersets.items() if value is not None}
    filtersets_getpid_to_plot = {key: value for key, value in filtersets_getpid.items() if value is not None}
    mechanisms_to_plot = list(mechanisms.values())[1:]

    x = np.arange(len(mechanisms_to_plot)).astype(np.float32)  # the label locations
    fig, ax = plt.subplots()

    # Bar plots
    args = {"edgecolor":"Black", "capsize":3}
    if test_name == "getpid":
        width = 1.0/len(filtersets_getpid_to_plot) * 0.85
        for index,(filter,filter_data) in enumerate(filtersets_getpid_to_plot.items()):
            yerr = data_processed["error"][filter][1:]
            width2 = (len(filtersets) + (len(filtersets_getpid_to_plot) % 2)) / 2
            rects = ax.bar(x + (1.5 - width2 + index) * width, data_processed["values"][filter][1:], width, yerr=yerr, **args, color=filter_data["color"], label=filter_data["label"])
            autolabel(rects, ax, yerr=yerr, size=font_small)
    else: # not getpid
        width = 1.0/len(filtersets_to_plot) * 0.9
        for index,(filter,filter_data) in enumerate(filtersets_to_plot.items()):
            yerr = data_processed["error"][filter][1:]
            width2 = (len(filtersets) + (len(filtersets_getpid_to_plot) % 2)) / 2
            rects = ax.bar(x + (1.5 - width2 + index) * width, data_processed["values"][filter][1:], width, yerr=yerr, **args, color=filter_data["color"], label=filter_data["label"])
            autolabel(rects, ax, yerr=yerr, size=font_small)

    plt.xticks(range(len(mechanisms_to_plot)), mechanisms_to_plot) # , rotation="60", horizontalalignment="right"
    ax.set_yscale("log")
    columns = 1
    ax.legend(
        frameon=False,
        borderpad=0.2, # default borderpad=0.4
        loc="upper right",
        ncol=columns,
        fontsize="small",
        bbox_to_anchor=(0.95,0.95),
        bbox_transform=plt.gcf().transFigure
    )
    if test_name == "getpid":
        ax.set_ylim(bottom=0.8, top=400)

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    plt.savefig(output_file + ".pdf", bbox_inches="tight", pad_inches=0)
    plt.close()


#-------------------------------------------------------------------------------

if __name__ == "__main__":
    try: 
        os.mkdir(output_dir)
    except:
        pass

    for test_name in all_data["none"]["none"]["data"].groupby(["syscall"]).groups:
        print(test_name)
        plot(test_name)
#-------------------------------------------------------------------------------
