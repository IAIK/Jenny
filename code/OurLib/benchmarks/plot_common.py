import scipy
#from scipy import stats
from matplotlib import rcParams
import shutil
from collections import OrderedDict
import numpy as np

#-------------------------------------------------------------------------------
def print_stats_datadicts(list_of_lists_of_datadicts):
    pre  = 0
    post = 0
    for list_of_datadicts in list_of_lists_of_datadicts:
        for datadict in (d for d in list_of_datadicts if d):
            pre  += datadict["num_samples_pre_filtering"]
            post += datadict["num_samples_post_filtering"]
    print("{} - {} = {} ({:.2f}%)".format(
        pre, 
        post, 
        pre - post,
        100*(1 - (datadict["num_samples_post_filtering"] / datadict["num_samples_pre_filtering"]))
    ))


def print_stats_single_datadict(datadict):
    print("-----------------------")
    print("num_samples_pre_filtering      ", datadict["num_samples_pre_filtering"])
    print("num_samples_post_filtering     ", datadict["num_samples_post_filtering"])
    print("lost samples {} = {:.1f}%".format(
            datadict["num_samples_pre_filtering"] - datadict["num_samples_post_filtering"],
            100*(1 - (datadict["num_samples_post_filtering"] / datadict["num_samples_pre_filtering"]))
    ))
    print("-----------------------")
#-------------------------------------------------------------------------------
def autolabel(rects, ax, xpos="center", fmt="{:.2f}", yerr=[], size=13, rotation=90):
    """Attach a text label above each bar in *rects*, displaying its height."""
    xpos = xpos.lower()  # normalize the case of the parameter
    for index,rect in enumerate(rects):
        height = rect.get_height()
        height = round(height,2) #+ 0.01 # rounding for nicer values
        if height == 0:
            continue

        barheight = height
        if len(yerr) > 0 and not np.isnan(yerr[index]):
            barheight += yerr[index]/2
        ax.annotate(fmt.format(height),
                    size=size,
                    rotation=rotation,
                    xy=(rect.get_x() + rect.get_width() / 2, barheight),
                    xytext=(0, 5),  # n points vertical offset
                    textcoords="offset points",
                    ha="center", 
                    va="bottom",
                    #annotation_clip=False,
                    #clip_on=True, 
                    )
#-------------------------------------------------------------------------------
def lighten_color(color, amount=0.5):
    import matplotlib.colors as mc
    import colorsys
    try:
        c = mc.cnames[color]
    except:
        c = color
    c = colorsys.rgb_to_hls(*mc.to_rgb(c))
    return colorsys.hls_to_rgb(c[0], 1 - amount * (1 - c[1]), c[2])
#-------------------------------------------------------------------------------
def mechanisms_to_dict(mechanisms, is_paper=True):
    assert(is_paper)
    _mechanism_names = OrderedDict([
        # internal name,    label
        ("nul",             "Native"),
        ("none",            "Jenny"),
        ("ptrace",          "ptrace"),
        ("ptrace_seccomp",  "ptrace_seccomp"),
        ("ptrace_delegate", "secccomp\n ptrace"),
        ("seccomp",         "seccomp"),
        ("seccomp_user",    "secccomp\n user"),
        ("sysmodule",       "pku-user-\ndelegate"),
        ("indirect",        "libc-\nindirect*")
    ])
    return OrderedDict([(k,_mechanism_names[k]) for k in mechanisms])
#-------------------------------------------------------------------------------
def filtersets_to_dict(filtersets):
    _all_filtersets = OrderedDict([
        ("none",              {"color":"White",                        "label":"none",              }),
        ("self-donky",        {"color":lighten_color("Green",   0.3),  "label":"base-donky*",       }),
        ("self-mpk",          {"color":lighten_color("Blue",    0.3),  "label":"base-mpk",          }),
        ("localstorage",      {"color":lighten_color("Orange",  0.3),  "label":"localstorage",      }),
        ("nginx",             {"color":lighten_color("Purple",  0.3),  "label":"nginx",             }),
    ])
    return OrderedDict([(k,_all_filtersets[k]) for k in filtersets])
#-------------------------------------------------------------------------------

def compute_ratio_std(vmean, vstd, smean, sstd):
    #overhead = (smean / vmean)
    vvar = pow(vstd, 2)
    svar = pow(sstd, 2)
    # Computing variance:
    # 1. Var(X+a) = Var(x) for a const.
    # 2. Var(X*b) = Var(x) * b² for b const.
    # 3. Variance of ratios
    #    var(S/V) approx. (µS/µV)^2 * [ varS/µS² + varV/µV² -2 Cov(R,V)/(µS*µV)]
    #    Cov(S,V) = 0 if independent
    #    See: www.stat.cmu.edu/~hseltman/files/ratio.pdf
    # Overall:
    # Var(overhead) = var(s/v) * 100²
    overheadvar = pow((smean / vmean),2) * ( (svar / pow(smean,2)) + (vvar / pow(vmean,2)) )
    overheadstd = scipy.sqrt(overheadvar)
    return overheadstd
#-------------------------------------------------------------------------------

def rcparamsstuff():
    # fix missing minus sign:
    #del matplotlib.font_manager.weight_dict['roman']
    #matplotlib.font_manager._rebuild()

    """
    font:
    may need to:
    $ sudo apt install msttcorefonts font-manager
    $ rm -rf ~/.cache/matplotlib
    """

    if shutil.which("latex") is not None:
        rcParams['text.usetex'] = True
    else:
        print("WARNING: latex not found in path. consider installing latex!")
    rcParams['text.latex.preamble']=r"\usepackage{times}\usepackage{underscore}" # Times New Roman
    rcParams['ps.fonttype']  = 42
    rcParams['pdf.fonttype'] = 42

    rcParams['font.family'] = ['serif']
    rcParams['font.serif'] = ['Times New Roman']

    rcParams['axes.unicode_minus'] = False

#-------------------------------------------------------------------------------
