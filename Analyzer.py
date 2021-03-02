import os
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter, MaxNLocator, FormatStrFormatter
import numpy as np
# Defined variables

plot_colors = ['b','g','r','c','m','y','k','tab:pink','tab:brown','tab:orange', 'brown', 'yellow', 'lightgreen', 'peru', 'lightpink']

# for attributes data structure
ATTRIBUTE_INDEX_SIZE = 0
ATTRIBUTE_INDEX_LABEL = 1
ATTRIBUTE_INDEX_GROUP = 2
ATTRIBUTE_INDEX_OUTPUTFORMAT = 3
ATTRIBUTE_INDEX_DELIMITER = 4
# following is important, for each Attibute we put the fields in the following order of indexing:
# 0:size, 1:label, 2:group, 3:label, 4:output-format, 5:delimiter
# NOTE: CA and GA differ on edge, on analyzer, it is only parsing output, we do not care about conditions that
# led to the value's existance


# 802.11n data rate mapping
# 20MHz bandwidth with 0.8us and 0.4us Guard Interval
bw20 = [6.5, 13, 19.5, 26, 39, 52, 58.5, 65, 7.2, 14.4, 21.7, 28.9, 43.3, 57.8, 65, 72.2]

# 40MHz bandwidth with 0.8us and 0.4us Guard Interval
bw40 = [13.5, 27, 40.5, 54, 81, 108, 121.5, 135, 15, 30, 45, 60, 90, 120, 135, 150]

# for bandwidth, HT format extraction fields within radiotap field in 802.11n

RADIOTAP_KNOWN_BW_MASK = 0x01
RADIOTAP_KNOWN_MCS_MASK = 0x02
RADIOTAP_KNOWN_GI_MASK = 0x04
RADIOTAP_KNOWN_HT_FORMAT_MASK = 0x08
RADIOTAP_FLAGS_GI = 0x04
RADIOTAP_FLAGS_HT_FORMAT = 0x08
RADIOTAP_FLAGS_BW = 0x03

# for tags data structure
TAG_INDEX_TARGET_ATTRIBUTE = 0
TAG_INDEX_LABEL = 1
TAG_INDEX_VAL = 2
TAG_INDEX_MAX = 3

# for view data structure
VIEW_INDEX_GRANULARITY = 0
VIEW_INDEX_START = 1
VIEW_INDEX_DURATION = 2
VIEW_INDEX_MAX = 3

# radiotap masks
PREAMBLE_FLAGS_BIT_MASK = 0x02
# RadioTap Constants
IEEE80211_RADIOTAP_TSFT = 0
IEEE80211_RADIOTAP_FLAGS = 1
IEEE80211_RADIOTAP_RATE = 2
IEEE80211_RADIOTAP_CHANNEL = 3
IEEE80211_RADIOTAP_FHSS = 4
IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5
IEEE80211_RADIOTAP_DBM_ANTNOISE = 6
IEEE80211_RADIOTAP_LOCK_QUALITY = 7
IEEE80211_RADIOTAP_TX_ATTENUATION = 8
IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9
IEEE80211_RADIOTAP_DBM_TX_POWER = 10
IEEE80211_RADIOTAP_ANTENNA = 11
IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12
IEEE80211_RADIOTAP_DB_ANTNOISE = 13
IEEE80211_RADIOTAP_RX_FLAGS = 14
IEEE80211_RADIOTAP_TX_FLAGS = 15
IEEE80211_RADIOTAP_RTS_RETRIES = 16
IEEE80211_RADIOTAP_DATA_RETRIES = 17

# 18 is XChannel, but it's not defined yet
IEEE80211_RADIOTAP_MCS = 19
IEEE80211_RADIOTAP_AMPDU_STATUS = 20
IEEE80211_RADIOTAP_VHT = 21
IEEE80211_RADIOTAP_TIMESTAMP = 22

# valid in every it_present bitmap, even vendor namespaces
IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29
IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30
IEEE80211_RADIOTAP_EXT = 31

ga_attr = []  # GA attributes labels
ct_attr = []  # CA attributes labels
attribs = {}
attribs['RT'] = []  # list of all RT attributes
attribs['GA'] = {}  # Hashamp of all GA attributes, mapped based on key, indexing explained below.
attribs['CA'] = {}  # Hashamp of all CA attributes, mapped based on key, indexing explained below.
log = []  # hashmap of the whole log, keys are associated with values per frame, so each frame an entry x and

# each entry x has hashmap inside of it that details it's parameters including duration
ga_keys = []
ca_keys = []

# Tags data structures
tags = {}
tags_counter = 0  # the counters are used as keys for each tag, this enables us to know how many tags quickly.
tags_keys = []
tags_labels = []
tag_index_labels = ['Target Attribute', 'Tag Label', 'Tag Value (or all for all distinct possible values']


# View data structure
view = [None] * VIEW_INDEX_MAX


def process_rt(buffer, lc, count):
    i = 0
    while i < len(attribs['RT']):
        field = attribs['RT'][i]
        if buffer[lc] == int.from_bytes('|'.encode(), "little"):
            lc += 1
            i += 1
            continue
        if field == IEEE80211_RADIOTAP_TSFT:
            tsftar = buffer[lc: lc + 7]  # 8 bytes for TSFT
            lc += 9
            # int.from_bytes(size, "little")
            TSFT = int.from_bytes(tsftar, "little")
            print('TSFT = ' + str(TSFT))
            log[count]['TSFT'] = TSFT
        if field == IEEE80211_RADIOTAP_FLAGS:
            flags = buffer[lc]  # 1 byte for flags
            log[count]['Flags'] = flags
            # flags = int.from_bytes(buffer[lc], "little")
            lc += 2
            print('Flags = ' + str(flags))
        if field == IEEE80211_RADIOTAP_RATE:
            rate = buffer[lc]  # 1 byte for rate (500Kbps)
            log[count]['Rate'] = rate
            lc += 2
            print('Rate = ' + str(rate))
        if field == IEEE80211_RADIOTAP_MCS:
            log[count]['known'] = buffer[lc]
            log[count]['flags'] = buffer[lc + 1] # NOTE: Case sensitive to differentiate between Flags and flags of 802.11n
            log[count]['mcs'] = buffer[lc + 2]
            print('mcs values are ' + str(buffer[lc]) + ', ' + str(buffer[lc + 1]) +', and ' + str(buffer[lc + 2]))
            lc += 4
        i += 1
    return lc


def process_ca(buffer, lc, buf_cnt, count):
    while lc < len(ca_keys):
        key = buffer[lc]
        if key in ca_keys:
            label = attribs['CA'][key][ATTRIBUTE_INDEX_LABEL]
            end_index = attribs['CA'][key][ATTRIBUTE_INDEX_SIZE] * attribs['CA'][key][ATTRIBUTE_INDEX_GROUP]
            log[count][label] = buffer[lc: lc + end_index]
            view_ga(label, key, count)
            lc += end_index
    return 0


def process_ga(buffer, lc, count):
    i = 0
    while i < len(ga_keys):
        key = ga_keys[i]
        label = attribs['GA'][key][ATTRIBUTE_INDEX_LABEL]
        end_index = attribs['GA'][key][ATTRIBUTE_INDEX_SIZE] * attribs['GA'][key][ATTRIBUTE_INDEX_GROUP]
        log[count][label] = buffer[lc: lc + end_index]
        view_ga(label, key, count)
        lc += end_index
        i += 1
    return 0


def is_eof(f):
    cur = f.tell()  # save current position
    f.seek(0, os.SEEK_END)
    end = f.tell()  # find the size of file
    f.seek(cur, os.SEEK_SET)
    return cur == end


def generate_tags_labels():
    i = 0
    target_attr_key = tags[0][TAG_INDEX_TARGET_ATTRIBUTE]
    tag_type = ''
    if target_attr_key in ga_keys:
        tag_type = 'GA'
        keys = ga_keys
        print('target attribute is a GA')
    if target_attr_key in ca_keys:
        print('target attribute is a CA')
        tag_type = 'CA'
        keys = ca_keys

    group = attribs[tag_type][target_attr_key][ATTRIBUTE_INDEX_GROUP]
    delimiter = attribs[tag_type][target_attr_key][ATTRIBUTE_INDEX_DELIMITER]
    size = attribs[tag_type][target_attr_key][ATTRIBUTE_INDEX_SIZE]
    output_format = attribs[tag_type][target_attr_key][ATTRIBUTE_INDEX_OUTPUTFORMAT]

    while i < len(tags_keys):
        str = ''
        ii = 0
        while ii < size:
            if group == 1:
                val = tags_keys[i][ii]
                str += obtain_val(val, output_format)
                str += delimiter
            else:
                val = tags_keys[i][ii * group:((ii + 1) * group) - 1]
                val = int.from_bytes(val, "little")
                str += obtain_val(val, output_format)
                str += delimiter
            ii += 1
        i += 1
        tags_labels.append(str)
    return


def process_tags(config):
    newtag = True
    global tags_counter
    while True:
        line = config.readline()
        line = line.rstrip('\n')
        if 'end' in line or is_eof(config):
            tags_counter += 1
            break
        elif '=' in line:
            str_tok = line.split('=')
            label = str_tok[0]
            value = str_tok[1]
            if newtag:
                newtag = False
                tags[tags_counter] = [None] * TAG_INDEX_MAX
                tags[tags_counter][TAG_INDEX_VAL] = []
            if label == 'tag-label':
                tags[tags_counter][TAG_INDEX_LABEL] = value
            elif label == 'attribute-target-key':
                tags[tags_counter][TAG_INDEX_TARGET_ATTRIBUTE] = value
            elif label == 'val':
                if 'all' in value:
                    tags[tags_counter][TAG_INDEX_VAL].append(value)
                    find_possible_tags(tags_counter)
                else:
                    if value not in tags_keys:
                        tags_keys.append(value)
    generate_tags_labels()


def process_view(config):
    while True:
        line = config.readline()
        line = line.rstrip('\n')
        if 'end' in line or is_eof(config):
            break
        elif ';' in line:
            break
        elif '=' in line:
            str_tok = line.split('=')
            label = str_tok[0]
            value = str_tok[1]
            if label == 'granularity':
                view[VIEW_INDEX_GRANULARITY] = value
                pass
            elif label == 'start':
                view[VIEW_INDEX_START] = value
                pass
            elif label == 'duration':
                view[VIEW_INDEX_DURATION] = value


def parse_config():
    config = open('config.txt', 'r')
    while True:
        line = config.readline()
        line = line.rstrip('\n')
        if is_eof(config):
            break
        if '.tag' in line:
            process_tags(config)
        elif '.view' in line:
            process_view(config)


def process_attribute(ADF, attr_type):
    line = ADF.readline()
    key = ''
    output_form = 'hex'
    delimiter = ''
    size = 0
    group = 0
    attr_label = ''
    rt_val = 0
    while '=' in line:
        line = line.rstrip('\n')
        str_tok = line.split('=')
        label = str_tok[0]
        value = str_tok[1]
        if label == 'key':
            key = value
        elif label == 'output-format':
            output_form = value
        elif label == 'size':
            size = int(value)
        elif label == 'group':
            group = int(value)
        elif label == 'delimiter':
            delimiter = value
        elif label == 'label':
            attr_label = value
        elif label == 'val':  # only in RT.
            rt_val = int(value)
            attribs[attr_type].append(rt_val)
        line = ADF.readline()
    # Radiotap headers are pre-defined by radiotap.org we only need bit to map rest and are entered based on
    if attr_type != 'RT':
        # following is important, for each Attibute we put the fields in the following order of indexing:
        # 0:size, 1:label, 2:group, 3:label, 4:output-format, 5:delimiter
        # must be either CA/GA and they both have the same parameters, CA has more fields but that is about it.
        if attr_type == 'GA':
            ga_keys.append(key)
        elif attr_type == 'CA':
            ca_keys.append(key)

        attribs[attr_type][key] = []
        attribs[attr_type][key].append(size)
        attribs[attr_type][key].append(attr_label)
        attribs[attr_type][key].append(group)
        attribs[attr_type][key].append(output_form)
        attribs[attr_type][key].append(delimiter)


# parse ADF
def parse_ADF():
    ADF = open('ADF.txt', 'r')
    while True:
        line = ADF.readline()
        line = line.rstrip('\n')
        if is_eof(ADF):
            break
        if '=' not in line:
            continue
        str_tok = line.split('=')
        label = str_tok[0]
        value = str_tok[1]
        if label == 'attribute-type':
            attr_type = value
            process_attribute(ADF, attr_type)
    ADF.close()
    print("ADF PARSING COMPLETE")
    print(attribs)


# to Parse output binary, we read all RT available first, GA, then CA at end.
# the code uses two buffer mechanisms similar to edge code, one big buffer to store large chunks and another that
# stores per frame to be consumed, etc.
def display(val, output_format):
    if output_format == 'hex':
        print(hex(val)[2:], end='')
    elif output_format == 'int':
        print(val, end='')

def obtain_val(val, output_format):
    ret = ''
    if output_format == 'hex':
        ret = hex(val)[2:]
    elif output_format == 'int':
        ret = val
    return ret

def view_ga(label, key, count):
    i = 0
    group = attribs['GA'][ga_keys[i]][ATTRIBUTE_INDEX_GROUP]
    size = attribs['GA'][ga_keys[i]][ATTRIBUTE_INDEX_SIZE]
    delimiter = attribs['GA'][ga_keys[i]][ATTRIBUTE_INDEX_DELIMITER]
    output_format = attribs['GA'][ga_keys[i]][ATTRIBUTE_INDEX_OUTPUTFORMAT]
    while i < size:
        if group == 1:
            val = log[count][label][i]
            display(val, output_format)
            print(delimiter, end='')
        else:
            val = log[count][label][i * group:((i + 1) * group) - 1]
            val = int.from_bytes(val, "little")
            display(val, output_format)
        i += 1

    while i < len(ga_keys):
        label = attribs['GA'][ga_keys[i]][ATTRIBUTE_INDEX_LABEL]
    print()


def parse_output():
    output = open('output.bin', 'rb')
    buffer = bytes()
    print("HERE")
    count = 0
    while not is_eof(output):
        buffer += output.read(20)
        buf_cnt = 0
        while buf_cnt < len(buffer) - 1:
            if buffer[buf_cnt] == int.from_bytes('\t'.encode(), "little") and buffer[buf_cnt + 1] == int.from_bytes(
                    '\n'.encode(), "little"):
                buf_cnt += 1
                break
            buf_cnt += 1
        if buf_cnt < len(buffer) - 1:
            lc = 0
        else:
            continue
        size = buffer[lc: lc + 3]
        lc += 4
        size = int.from_bytes(size, "little")
        print('Size = ' + str(size))
        # new entry for frame
        log.append({})  # add new entry for frame
        log[count]['Size'] = size

        lc = process_rt(buffer, lc, count)
        if buffer[lc] == int.from_bytes('|'.encode(), "little"):
            lc += 1
        lc = process_ga(buffer, lc, count)
        process_ca(buffer, lc, buf_cnt, count)

        buffer = buffer[buf_cnt + 1:]
        print()
        count += 1
        # process all GA


# calculates duration per frame. If a frame does not have rate value nor MCS for 802.11n rates we assume
# 1Mbps which is conservative. However, that does not occur many times so it is a reasonable assumption to represent medium
def calculate_durations():
    count11n = 0
    long_preamble = 192  # 192 microseconds for long preamble
    short_preamble = 96  # 96 microseconds for short preamble
    plcp_header = 4  # 4 microseconds for header
    i = 0
    frame11n = False
    while i < len(log):
        duration = 0
        frame11n = False
        rate_bps = 1000000  # 1Mbps default if no rate can be selected based on available information
        # calculate duration for 802.11n data rates
        if 'known' in log[i].keys():
            frame11n = True
            count11n +=1
            gifound = log[i]['known'] & RADIOTAP_KNOWN_GI_MASK
            htfound = log[i]['known'] & RADIOTAP_KNOWN_HT_FORMAT_MASK
            bwfound = log[i]['known'] & RADIOTAP_KNOWN_BW_MASK
            mcsfound = log[i]['known'] & RADIOTAP_KNOWN_MCS_MASK

            giadd = 0

            # automatically use short preamble for 802.11n
            duration += short_preamble
            # If guard interval indicator is stated
            if gifound != 0:
                if log[i]['flags'] & RADIOTAP_FLAGS_GI != 0:
                    giadd = 8 # i.e. use short GI rates
                else:
                    giadd = 0 # i.e. use long GI rates
            # If HT format indicator is stated
            if htfound != 0:
                if log[i]['flags'] & RADIOTAP_FLAGS_HT_FORMAT == 0:
                    duration += 40 # L-STF + L-LTF + L-SIG + HT-SIG + HT-STF + HT-LTFs = 40us (mixed mode)
                elif log[i]['flags'] & RADIOTAP_FLAGS_HT_FORMAT == 1:
                    duration += 28 # L-STF + HT-LTF1 + HT-SIG + HT-LTFs ~= 28 us (greenfield mode)
            else:
                duration += 20 # L-STF + L-LTF + L-SIG = 20us (legacy mode)

            #get rate
            rate = 1 # 1Mbps default
            if mcsfound != 0:
                mcs = log[i]['mcs']
                print('HERE mcs found = ' + str(mcs))
                if bwfound != 0:
                    if log[i]['flags'] & RADIOTAP_FLAGS_BW == 1:
                        rate = bw40[mcs + giadd]
                    else:
                        rate = bw20[mcs+giadd]
                print('rate selected is ' + str(rate) + 'mcs + giadd = ' + str(mcs+giadd))
            rate_bps = rate * 1000000  # convert to bps
        elif 'Flags' in log[i].keys() and not frame11n:
            preamble = log[i]['Flags'] & PREAMBLE_FLAGS_BIT_MASK
            if preamble == 1:
                duration += short_preamble
            else:
                duration += long_preamble
        else:
            print('could not find flags indicating preamble of frame, assuming long preamble')
            duration += long_preamble
        duration += plcp_header  # 4 microseconds plcp header
        size_bits = log[i]['Size'] * 8
        # calculate duration based on data rate of the frame
        if 'Rate' in log[i].keys() and not frame11n:
            rate_bps = log[i]['Rate'] * 500 * 1000  # convert to bps
        rate_bpus = rate_bps / 1000000  # rate for 1 us
        time = (size_bits * rate_bpus)  # duration of frame in microsecond
        duration += time
        # print('size ' + str(size_bits) + ' rate: ' + str(rate_bps) + 'preamble = ' + str(preamble) + 'frame time beside preamble ' + str(time))
        # print(duration)
        log[i]['duration'] = duration
        i += 1
    print('total of 11n frames wtih mcs = ' + str(count11n))

def find_tag_label(tag_index):
    target_attr_key = tags[tag_index][TAG_INDEX_TARGET_ATTRIBUTE]
    tag_type = ''
    if target_attr_key in ga_keys:
        tag_type = 'GA'
        print('target attribute is a GA')
    if target_attr_key in ca_keys:
        print('target attribute is a CA')
        tag_type = 'CA'

    if tag_type == '':
        print('cannot find tag type, please revise your tag section')
        exit(0)

    label = attribs[tag_type][target_attr_key][ATTRIBUTE_INDEX_LABEL]
    return label

def find_possible_tags(tag_index):
    i = 0
    label = find_tag_label(tag_index)
    while i < len(log):
        if log[i][label] not in tags_keys:
            tags_keys.append(log[i][label])
        i+= 1

def tag_view():
    fig, axl = plt.subplots()
    ytiks =  [0, 25, 50, 75, 100]
    print('tag and view')
    beginning = log[0]['TSFT']
    granularity = int(view[VIEW_INDEX_GRANULARITY])
    duration = int(view[VIEW_INDEX_DURATION])
    vbeg = beginning + int(view[VIEW_INDEX_START]) #view plot beginning of x axis
    vend = duration + vbeg
    nopts = duration / granularity
    label = find_tag_label(0)
    target_attr = None
    lines = []
    nolines = 1
    if tags_counter > 0:
        target_attr = label
        nolines = len(tags_keys)
    else:
        target_attr = None

    i = 0
    while i < nolines:
        lines.append([0] * int(nopts))
        i += 1
    print('number of different lines is: ' + str(nolines))

    i = 0 # iterator for frames TSFT
    util = [0] * (len(lines))
    pts = 0 # iterator for bars i.e. number of bars to log utilization at.
    while vbeg < vend and log[i]['TSFT'] < vend:
        # If frame utilization (or some part of it) fall within granularity bar
        #print('vbeg = ' + str(vbeg) + 'and i = ' + str(i) + ' with TSFT ' + str(log[i]['TSFT']))
        if vbeg < (log[i]['TSFT'] + log[i]['duration']) and vbeg + granularity > log[i]['TSFT']:
            # frame can be one of the following:
            #   - starting before beginning of bar
            #   - ending after ending of bar
            #   - completely within
            frame_dur = log[i]['duration']
            index = tags_keys.index(log[i][label]) #TAKE ME OFF
            if vbeg > log[i]['TSFT']:
                if index == 6:
                    print('Removing beginning')
                frame_dur = frame_dur - (vbeg - log[i]['TSFT'])

            if vbeg + granularity < log[i]['duration'] + log[i]['TSFT']:
                if index == 6:
                    print('Removing ending')
                frame_dur = frame_dur - ((log[i]['duration'] + log[i]['TSFT']) - (vbeg + granularity))

            if target_attr == None:
                util[0] += frame_dur
            else:
                index = tags_keys.index(log[i][label])
                util[index] += frame_dur
#                if index == 6:
#                   print('Size = ' + str(log[i]['Size'])+ 'frame duration is ' + str(log[i]['duration']) + ' and its TSFT is ' + str(log[i]['TSFT']) + ' and beg ' + str(vbeg) +  ' ending ' + str(vbeg+granularity))
#                   print('util value = ' + str(util[index]))

            #special cases #1, means we need to also increment all bars and move to next one
            if vbeg + granularity < log[i]['duration'] + log[i]['TSFT']:
                #FIXME: Repeated code, should be placed in function better
                if target_attr == None:
                    lines[0][pts] = util[0] / granularity
                else:
                    jj = 0
                    while jj < len(util):
                       # if jj == 6:
                            #print('util value is ' + str(util[jj]))
                        lines[jj][pts] = util[jj]/granularity
                        if lines[jj][pts] > 1:
                            print('WTF [' + str(jj)+ '][' + str(pts) +'] = ' + str( lines[jj][pts]))
                        jj += 1
                jj = 0
                while jj < len(util):
                    util[jj] = 0
                    jj += 1
                vbeg += granularity
                pts += 1
            #special case #2, means we need to increment frame as it lied on boundary of beginning of bars
            if vbeg + granularity >log[i]['duration'] + log[i]['TSFT']:
                i += 1
        # If frame is behind beginning of bars, move to next frame
        if vbeg > log[i]['TSFT'] + log[i]['duration']:
            i += 1

        # If bar ending is behind beginning of frame TSFT, add all calculated utilizations, move to next bar, and reset
        # utils values to zero
        if vbeg + granularity <= log[i]['TSFT']:
            if target_attr == None:
                lines[0][pts] = util[0] / granularity
            else:
                jj = 0
                while jj < len(util):
#                    if jj == 6:
#                        print('util value is ' + str(util[jj]) + 'granularity = ' + str(granularity))
                    lines[jj][pts] = util[jj] / granularity
                    if lines[jj][pts] > 1:
                            print('WTF [' + str(jj)+ '][' + str(pts) +'] = ' + str(lines[jj][pts]))
                    jj += 1
            jj = 0
            while jj < len(util):
                util[jj] = 0
                jj += 1
            vbeg += granularity
            pts += 1
    print(lines[1])
    print('first TSFT of frame is ' + str(beginning))
    print('starting point is ' + str(vbeg))
    print('ending point is ' + str(vend))
    print('number of points will be ' + str(nopts))
    print('number of tags is ' + str(len(lines)))
    jj = 0
    while jj < len(lines):
        plt.plot(np.arange(pts), lines[jj], linestyle='-',label=tags_labels[jj], linewidth=3, color=plot_colors[jj])
        jj += 1
    plt.yticks(size = 25)
    plt.xticks(size = 25)
    plt.locator_params(axis = 'y', nbins = 5)
    axl.yaxis.set_major_formatter(PercentFormatter(1.0))
    axl.set_ylim(0, 1)
    plt.title('Medium Utilization with ' + tags[0][TAG_INDEX_LABEL], fontsize=18)
    plt.xlabel('Time (' + str(view[VIEW_INDEX_GRANULARITY]) + 'us)', fontsize = 18)
    plt.ylabel('Medium Utilization (%)', fontsize = 18)
    plt.legend(fontsize = 15)
    plt.tight_layout()

    plt.show()





def view_config():
    i = 0
    print('here ' + str(tags_counter))
    while i < tags_counter:
        j = 0
        print('Tag no.' + str(i))
        entry = tags[i]
        while j < TAG_INDEX_MAX:
            print(tag_index_labels[j] + ' = ' + entry[j][0],)
            j += 1
        print()
        i += 1


def main():
    parse_ADF()
    parse_output()
    parse_config()
    calculate_durations()
    view_config()
    tag_view()


main()
