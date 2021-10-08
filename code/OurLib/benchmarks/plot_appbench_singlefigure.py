#!/usr/bin/env python3
from collections import OrderedDict
import sys
import numpy as np
import matplotlib.pyplot as plt
from matplotlib import lines
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
font_small = 10
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
    datadict["groups_set"] = set([g for g in groups.groups])
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
    src_dir = sys.argv[1]
    if len(sys.argv) > 2:
        assert sys.argv[1] == "paper"
        src_dir = sys.argv[2]
        paper = True
    dst_file = src_dir + "/appbench_single"

    mechanisms = mechanisms_to_dict([
        #"ptrace", 
        "ptrace_delegate", 
        #"seccomp_user", 
        "sysmodule", 
        "indirect",
    ], paper)

    filtersets = filtersets_to_dict([
        "none",
        "self-donky",
        "self-mpk",
        "localstorage",
    ])

    files = [
        ("output_dd.csv",         "dd"),
        ("output_git.csv",        "git"),
        ("output_ls.csv",         "ls"),
        ("output_openssl.csv",    "openssl"),
        ("output_zip.csv",        "zip"),
        ("output_ffmpeg.csv",     "ffmpeg"),
    ]
    files = [(src_dir + "/" + f, name) for (f,name) in files]

    everything = OrderedDict()
    for f,_ in files:
        everything[f] = {}
        everything[f]["data"] = get_all_values([f], 0)

    def get_field(data, field, mechanism, filt):
        try:
            return int(data[field].loc[mechanism].loc[filt][0])
        except:
            print(colored("Warning: missing {}/{}/{}".format(field, mechanism, filt), 'red'))
            return 0

    def get_field_for_each_mechanism(data, field, filt):
        results = []
        for mechanism in mechanisms.keys():
            if (mechanism, filt) in data["groups_set"]:
                results.append(get_field(data, field, mechanism, filt))
            else:
                results.append(0)
        return results

    def data_to_normalized_mean(data, filt, baseline_mean):
        return [val / baseline_mean for val in get_field_for_each_mechanism(data, "mean", filt)]

    def data_to_error(data, filt, baseline_mean, baseline_std):
        means              = np.asarray(get_field_for_each_mechanism(data, "mean", filt))
        raw_errors         = np.asarray(get_field_for_each_mechanism(data, "std", filt))
        errors = compute_ratio_std(baseline_mean, baseline_std, means, raw_errors)
        return errors

    for f in everything.keys():
        data = everything[f]["data"]
        everything[f]["baseline_mean"] = get_field(data, "mean", "none", "none")
        everything[f]["baseline_std"] = get_field(data, "std", "none", "none")

        everything[f]["data_processed"] = {}
        everything[f]["data_processed"]["values"] = {}
        everything[f]["data_processed"]["error"] = {}

        for filterset in filtersets.keys():
            everything[f]["data_processed"]["values"][filterset] = data_to_normalized_mean(data, filterset, everything[f]["baseline_mean"])
            everything[f]["data_processed"]["error"][filterset] = data_to_error(data, filterset, everything[f]["baseline_mean"], everything[f]["baseline_std"])


    # plot
    rcParams["figure.figsize"] = 12,2.0
    x = np.arange(len(everything) * len(mechanisms)).astype(np.float32)  # the label locations
    fig, ax = plt.subplots()

    args = {"edgecolor":"Black", "capsize":3}

    filter = "localstorage"
    width = 1/len(filtersets) * 0.8

    for filt_index, filt_str in enumerate(filtersets.keys()):
        #~ labels_to_plot = [ b + mechanism_str for b in everything.keys() for (mechanism, mechanism_str) in enumerate(mechanisms)]
        data_to_plot = [ everything[b]["data_processed"]["values"][filt_str][mech_index] for b in everything.keys() for mech_index,_ in enumerate(mechanisms.items())]
        error_to_plot = [ everything[b]["data_processed"]["error"][filt_str][mech_index] for b in everything.keys() for mech_index,_ in enumerate(mechanisms.items())]

        width2 = width
        #width2 = (len(mechanisms) + (len(mechanisms) % 2)) / 2
        rects1 = ax.bar(x + (-1.5 + filt_index) * width, data_to_plot, width, yerr=error_to_plot, **args, color=filtersets[filt_str]['color'], label=filtersets[filt_str]["label"])
        autolabel(rects1, ax, yerr=error_to_plot, size=font_small)

    plt.xticks(range(len(x)), [mechanism_str  for f,name in files for mechanism_str in mechanisms.values()], rotation="0")
    
    benchmarks = [name for f,name in files]
    ylim = 125
    ymin = 0.8

    yoff = -1
    xoff = 1
    breadth = len(mechanisms)
    for b in benchmarks:
        coord = ax.transLimits.transform((xoff, yoff))
        plt.text(coord[0], coord[1], b, fontsize=12, ha='center', transform=plt.gcf().transFigure)
        xoff += breadth

    xoff = 1 + breadth/2
    for b in benchmarks[:-1]:
        line = lines.Line2D([xoff, xoff], [ylim,ymin/2], color="gray", linewidth=1)
        line.set_clip_on(False)
        ax.add_line(line)
        xoff += breadth

    ax.legend(
        frameon=False,
        borderpad=0.4, # default borderpad=0.4
        loc="upper right",
        ncol=1
    )
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    axes = plt.gca()
    axes.set_ylim([ymin, ylim]) # not needed when we dont show the top spine/border

    ax.set_yscale("log")
    ax.margins(x=0.01)
    plt.tight_layout()
    plt.savefig(dst_file + ".pdf", bbox_inches="tight", pad_inches=0)
    print(dst_file + ".pdf")

#-------------------------------------------------------------------------------
