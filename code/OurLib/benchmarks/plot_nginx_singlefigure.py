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
    dst_file = src_dir + "/appbench_nginx_single"

    mechanisms = mechanisms_to_dict([
        #"ptrace", 
        "ptrace_delegate", 
        #"seccomp_user", 
        "sysmodule", 
        "indirect",
    ], paper)
    mechanism_colors = OrderedDict([
        ("native",          "Cyan"),
        ("ptrace_delegate", lighten_color("Black",   0.05)),
        ("sysmodule",       lighten_color("Black",   0.40)),
        ("indirect",        lighten_color("Black",   0.70)),
    ])

    filtersets = filtersets_to_dict([ "nginx" ])
    kb = "0"
    files = [
        ("output_nginx_"+kb+"KiB.csv",              "No modules"),
        ("output_nginx_gzip_"+kb+"KiB.csv",         "gzip"),
        ("output_nginx_auth_gzip_"+kb+"KiB.csv",    "gzip + auth"),
    ]
    files_native = [ f.replace("nginx", "nginx_native") for (f,n) in files]
    files = [(src_dir + "/" + f, name) for (f,name) in files]
    files_native = [src_dir + "/" + f for f in files_native]

    everything = OrderedDict()
    for idx, (f,_) in enumerate(files):
        everything[f] = {}
        everything[f]["data"] = get_all_values([f], 0)
        everything[f]["native"] = get_all_values([files_native[idx]], 0)

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
        native = everything[f]["native"] # Take baseline from native nginx
        data = everything[f]["data"]
        everything[f]["baseline_mean"] = get_field(native, "mean", "none", "none")
        everything[f]["baseline_std"] = get_field(native, "std", "none", "none")

        everything[f]["normalized"] = {}
        everything[f]["normalized"]["values"] = {}
        everything[f]["normalized"]["error"] = {}

        for filterset in filtersets.keys():
            everything[f]["normalized"]["values"][filterset] = data_to_normalized_mean(data, filterset, everything[f]["baseline_mean"])
            everything[f]["normalized"]["error"][filterset] = data_to_error(data, filterset, everything[f]["baseline_mean"], everything[f]["baseline_std"])

    # plot
    rcParams["figure.figsize"] = 6,1.3
    x = np.arange(len(everything)).astype(np.float32)  # the label locations
    fig, ax = plt.subplots()
    filter = "nginx"
    args = {"edgecolor":"Black", "capsize":3}
    width = 1/len(mechanisms) * 0.8

    for mech_index,(mechanism, mechanism_str) in enumerate(mechanisms.items()):
        #labels_to_plot = [ b + mechanism_str for b in everything.keys()]
        label = mechanism_str.replace("\n", "")
        data_to_plot = [ everything[f]["normalized"]["values"][filter][mech_index] for f in everything.keys()]
        error_to_plot = [ everything[f]["normalized"]["error"][filter][mech_index] for f in everything.keys()]

        width2 = width
        rects1 = ax.bar(x + (-1.5 + mech_index) * width, data_to_plot, width, yerr=error_to_plot, **args, color=mechanism_colors[mechanism], label=label)
        autolabel(rects1, ax, yerr=error_to_plot, size=font_small, rotation=0)


    plt.xticks(range(len(x)), [name for f,name in files], rotation="0")
    
    ymax = 2.9
    ymin = 0

    ax.legend(
        frameon=False,
        borderpad=0.4, # default borderpad=0.4
        loc="upper right",
        ncol=3
    )

    axes = plt.gca()
    axes.set_ylim([ymin, ymax])
    ax.margins(x=0.01)
    plt.tight_layout()
    plt.savefig(dst_file + ".pdf", bbox_inches="tight", pad_inches=0)
    plt.show(block=False)
    print(dst_file + ".pdf")

#-------------------------------------------------------------------------------
