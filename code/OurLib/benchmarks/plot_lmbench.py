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
    dst_file = src_dir + "/lmbench"

    mechanisms = mechanisms_to_dict([
        #"ptrace", 
        "ptrace_delegate", 
        #"seccomp_user", 
        "sysmodule", 
        "indirect",
    ], paper)
    mechanism_colors = OrderedDict([
        ("ptrace_delegate", lighten_color("Black",   0.05)),
        ("sysmodule",       lighten_color("Black",   0.35)),
        ("indirect",        lighten_color("Black",   0.65)),
    ])

    files = [
        ("output_lat_syscall_null.csv",        "syscall null"),
        ("output_lat_syscall_open.csv",        "syscall open"),
        ("output_lat_syscall_read.csv",        "syscall read"),
        ("output_lat_syscall_stat.csv",        "syscall stat"),
        ("output_lat_syscall_fstat.csv",       "syscall fstat"),
        ("output_lat_syscall_write.csv",       "syscall write"),
        ("output_lat_sig_catch.csv",           "sig catch"),
        ("output_lat_sig_install.csv",         "sig install"),
        ("output_lat_sig_prot_lat_sig.csv",    "sig prot"),
        ("output_lat_pipe.csv",                "pipe"),
        ("output_lat_unix.csv",                "unix"),
        ("output_lat_mmap_512k.csv",           "mmap 512k"),
        ("output_lat_pagefault.csv",           "pagefault"),
        ("output_lat_proc_fork.csv",           "proc fork"),
        ("output_lat_select_10_file.csv",      "select file"),
        ("output_lat_select_10_tcp.csv",       "select tcp"),
        ("output_lat_connect_localhost.csv",   "connect"),
        ("output_lat_http_localhost.csv",      "http"),
        ("output_lat_tcp_localhost.csv",       "tcp"),
        ("output_lat_udp_localhost.csv",       "udp"),
        ("output_bw_unix.csv",                 "bw_unix"),
        ("output_bw_tcp_1.csv",                "bw_tcp"),
        ("output_lmdd_100m.csv",               "lmdd 100m"),
    ]
    files = OrderedDict([(src_dir + "/" + f, name) for (f,name) in files])

    everything = OrderedDict()
    for f,_ in files.items():
        everything[f] = {}
        try:
            _data = get_all_values([f], 0)
            everything[f]["data"] = _data
        except Exception as e:
            print(e)
            del everything[f]

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

    filtersets = filtersets_to_dict([
        #"none",
        #"self-donky",
        #"self-mpk",
        "localstorage",
    ])

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
    rcParams["figure.figsize"] = 6,3
    x = np.arange(len(everything)).astype(np.float32)  # the label locations
    fig, ax = plt.subplots()
    args = {"edgecolor":"Black", "capsize":3}

    filter = "localstorage"
    width = 1/len(mechanisms) * 0.9

    rects = OrderedDict()
    for mech_index,(mechanism, mechanism_str) in enumerate(mechanisms.items()):
        yval = [ everything[f]["data_processed"]["values"][filter][mech_index] for f in everything.keys() ]
        yerr = [ everything[f]["data_processed"]["error"][filter][mech_index] for f in everything.keys() ]
        rects1 = ax.bar(x + (-1 + mech_index) * width, yval, width, yerr=yerr, **args, color=mechanism_colors[mechanism], label=mechanism_str)
        rects[mechanism] = rects1

    xticks = [files[f] for f in everything.keys()]
    plt.xticks(range(len(xticks)), xticks, rotation="90")

    ax.legend(
        frameon=False,
        borderpad=0.4, # default borderpad=0.4
        loc="upper right",
        ncol=3
    )
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.set_ylim(bottom=0.8, top=400)

    axes = plt.gca()
    ax.set_yscale("log")
    plt.tight_layout()
    plt.savefig(dst_file + ".pdf", bbox_inches="tight", pad_inches=0)

    print(dst_file + ".pdf")

    for mech_index,(mechanism, mechanism_str) in enumerate(mechanisms.items()):
        autolabel(rects[mechanism], ax, yerr=[], size=6)
    plt.savefig(dst_file + "_numbers.pdf", bbox_inches="tight", pad_inches=0)

    plt.close()
#-------------------------------------------------------------------------------
