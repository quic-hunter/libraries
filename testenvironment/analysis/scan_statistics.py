import argparse
import os
import io

import pandas as pd
import pyshark


folderName = ""
frame_servers: pd.DataFrame
output_file: io.TextIOWrapper


# Prints the statistics for ZMap
def statistics_ZMap():
    write("----------- ZMap statistics -----------")

    # prefer classified output if available
    fileName = "output_zmap.csv"
    if os.path.isfile(folderName + "output/zmap/output_zmap_classified.csv"):
        fileName = "output_zmap_classified.csv"

    frame_zmap = pd.read_csv(folderName + "output/zmap/" + fileName)

    if not frame_zmap[~frame_zmap.classification.str.startswith("quic")].empty:
        write("THERE ARE TARGETS NOT CLASSIFIED AS QUIC!")
    
    if not frame_zmap[frame_zmap.success != 1].empty:
        write("THERE ARE FOUND TARGETS WITHOUT SUCCESS!")

    frame_zmap_notFound = frame_servers[~frame_servers.ip.isin(frame_zmap.saddr)]
    frame_zmap_notFound = frame_zmap_notFound.sort_values("name")
    
    printCountWithPercent(frame_servers.shape[0], frame_zmap.shape[0], frame_zmap_notFound.shape[0],
            "Targets found by ZMap")
    if frame_zmap_notFound.shape[0] > 0:
        print_list(frame_zmap_notFound.name, "Servers not found by ZMap")


# Prints the statistics for QScanner
def statistics_QScanner():
    write("--------- QScanner statistics ---------")

    frame_qscanner = pd.read_csv(folderName + "output/qscanner/quic_connection_info.csv")

    if frame_qscanner.shape[0] != frame_servers.shape[0]:
        write("QSCANNER OUTPUT DOES NOT CONTAIN ALL SERVERS!")

    frame_qscanner_join = frame_qscanner.merge(frame_servers, how="inner", left_on="address", right_on="ip")
    frame_qscanner_success = frame_qscanner_join[frame_qscanner_join.errorMessage.isnull()]
    frame_qscanner_error = frame_qscanner_join[frame_qscanner_join.errorMessage.notnull()]

    frame_qscanner_success = frame_qscanner_success.sort_values("name")
    frame_qscanner_error = frame_qscanner_error.sort_values("name")

    printCountWithPercent(frame_qscanner_join.shape[0], frame_qscanner_success.shape[0],
        frame_qscanner_error.shape[0], "Targets successful with QScanner")

    if frame_qscanner_error.shape[0] > 0:
        write("Error targets with QScanner")
        for _, element in frame_qscanner_error.iterrows():
            write("\t",  element["name"] + ": " + element["errorMessage"])
        write("Error message distribution")
        counts = frame_qscanner_error.errorMessage.value_counts()
        counts.index = counts.index.map(lambda x: "         " + x)
        write(counts)

    frame_qscanner_retry = frame_qscanner_join[frame_qscanner_join.hasRetry == True]
    if frame_qscanner_retry.shape[0] > 0:
        print_list(frame_qscanner_retry.name, "Targets that required a Retry")
    
    checkVersions = True
    if checkVersions and frame_qscanner_success.shape[0] > 0:
        write("QScanner Version Statistic")
        for _, element in frame_qscanner_success.iterrows():
            write("\t",  element["name"] + ":  \t" + str(element["quicVersion"]))


# Prints information extracted from the packet capture
def statistics_capture():
    write("-------- Wireshark statistics ---------")

    # FROM https://ask.wireshark.org/question/27577/filter-for-tls13-helloretryrequest/
    HRR_filter = "tls.handshake.random == cf:21:ad:74:e5:9a:61:11:be:1d:8c:02:1e:65:b8:91:c2:a2:11:16:7a:bb:8c:5e:07:9e:09:e2:c8:a8:33:9c"
    capture_HRR = pyshark.FileCapture(folderName + "output/capture.pcapng", display_filter=HRR_filter)

    HRR_IPs = []
    for packet in capture_HRR:
        HRR_IPs.append(packet.ip.src)
    HRR_servers = frame_servers[frame_servers.ip.isin(HRR_IPs)]
    HRR_servers = HRR_servers.sort_values("name")
    if HRR_servers.shape[0] > 0:
        print_list(HRR_servers.name, "Servers that sent Hello Retry Requests")

    retry_filter = "quic and quic.long.packet_type==3"
    capture_retry = pyshark.FileCapture(folderName + "output/capture.pcapng", display_filter=retry_filter)

    retry_IPs = []
    for packet in capture_retry:
        retry_IPs.append(packet.ip.src)
    retry_servers = frame_servers[frame_servers.ip.isin(retry_IPs)]
    retry_servers = retry_servers.sort_values("name")
    if retry_servers.shape[0] > 0:
        print_list(retry_servers.name, "Servers that sent a Retry")


# Possibility to steer output differently in the future
def write(*out: str):
    elems = []
    for x in out:
        elems.append(str(x))
    output_file.write(" ".join(elems) + "\n")


# Prints the label and success and error count including relative percentage
def printCountWithPercent(total: int, success: int, error: int, label: str):
    write(label)
    write("\t  Total:", total)
    write("\tSuccess:", success, "({}%)".format(round(100 * success / total, 2)))
    write("\t  Error:", error, "({}%)".format(round(100 * error / total, 2)))


# Prints the label followed by each list entry
def print_list(input_list: list, label: str):
    write(label)
    for element in input_list:
        write("\t", element)


# Main entry point
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory",required=True, help="directory with scan results")
    args = parser.parse_args()

    global folderName
    folderName = args.directory

    if not folderName.endswith("/"):
        folderName = folderName + "/"

    if not os.path.exists(folderName):
        print("The specified folder does not exist.")
        return
    
    global output_file
    output_file = open(folderName + "statistics.txt", "w")

    global frame_servers
    frame_servers = pd.read_csv(folderName + "server_mapping.csv")
    write("Total servers:", frame_servers.shape[0])
    
    if os.path.exists(folderName + "output/zmap/"):
        statistics_ZMap()
    if os.path.exists(folderName + "output/qscanner/"):
        statistics_QScanner()
    if os.path.isfile(folderName + "output/capture.pcapng"):
        statistics_capture()
    
    output_file.close()


if __name__ == "__main__":
    main()
