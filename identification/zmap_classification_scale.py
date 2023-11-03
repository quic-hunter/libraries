import argparse
import os

import pandas as pd

0: bytearray

# QUIC Initial fixed bits and mask
initial_header = 0b11000000
initial_header_mask = 0b11000000

# QUIC Version Negotiation fixed bits and mask
vn_header = 0b10000000
vn_header_mask = 0b10000000


# returns [saddr, classification, success, versions] of a single row
def classify(row):
    global sent
    data = row["data"]
    saddr = row["saddr"]

    if not isinstance(data, str):
        return [saddr, "err-data", 0, ""]

    recv = bytearray.fromhex(data)

    if len(recv) < 6 or len(sent) < 6:
        return [saddr, "err-short", 0, ""]

    sent_src_id_start = 5 + sent[5] + 1
    recv_src_id_start = 5 + recv[5] + 1
    
    # Version Negotiation packet: match header and version
    if (vn_header & vn_header_mask) == (recv[0] & vn_header_mask) and (recv[1:5] == bytearray.fromhex("00000000")):

        # Check if src and dest connection IDs are as expected
        if conn_id_match(sent, sent_src_id_start, recv, 5) and conn_id_match(sent, 5, recv, recv_src_id_start):
            if len(recv) <= recv_src_id_start:
               return [saddr, "quic-vn-err-short", 0, ""]
         
            # extract versions
            recv_versions_start = recv_src_id_start + recv[recv_src_id_start] + 1
            versions_len = len(recv) - recv_versions_start
            if versions_len % 4 != 0:
                return [saddr, "quic-vn-err-length", 0, ""]
            
            versions = []
            for i in range (versions_len // 4):
                version_begin = recv_versions_start + i * 4
                versions.append(recv[version_begin:(version_begin + 4)].hex())

            return [saddr, "quic-vn", 1, " ".join(versions)]
        return [saddr, "quic-vn-err-cid", 0, ""]

    # Long Header packet: match header and version
    if (initial_header & initial_header_mask) == (recv[0] & initial_header_mask) and (recv[1:5] == sent[1:5]):

        # Check if the sent src connection ID is used as dst now
        if conn_id_match(sent, sent_src_id_start, recv, 5):
            return [saddr, "quic-lh", 1, recv[1:5].hex()]
        return [saddr, "quic-lh-err-cid", 0, ""]
    
    return [saddr, "err-head", 0, ""]


# Compare two connection IDs starting at their length fields
def conn_id_match(left: bytearray, left_start: int, right: bytearray, right_start: int):
    if left_start >= len(left) or right_start >= len(right):
        return False
    
    # check if lengths match
    if left[left_start] != right[right_start]:
        return False
    
    # check each byte of ID
    for i in range(left[left_start]):
        if (left_start + i + 1) >= len(left) or (right_start + i + 1) >= len(right):
            return False
        if left[left_start + i + 1] != right[right_start + i + 1]:
            return False

    return True


# Main entry point
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-z", "--zmap",required=True, help="ZMap file")
    parser.add_argument("-i", "--inital", required=True, help="used inital for the ZMap scan")
    parser.add_argument("-o", "--output", required=True, help="output file")
    args = parser.parse_args()

    if not os.path.isfile(args.zmap):
        print("The passed input file does not exist:", parser.zmap)
        return
    if not os.path.isfile(args.zmap):
        print("The passed Initial raw file does not exist:", parser.zmap)
        return

    # load the initial

    initial_file = open(args.zmap, "rb")
    global sent
    sent = bytearray(initial_file.read())
    initial_file.close()

    # load the data set

    zmap_output = pd.read_csv(args.zmap)

    # Make sure this output does contain the raw data
    if not "data" in zmap_output.columns:
        print("This does not look like a raw ZMap UDP scan output since column 'data' is missing.")
        return

    zmap_output = zmap_output[(zmap_output.classification == "udp") & (zmap_output.success == 1)]

    result = zmap_output.apply(lambda x: classify(x), axis=1, result_type = "expand")
    result.columns = ["saddr", "classification", "success", "versions"]
    result.to_csv(args.output, index=False)


if __name__ == "__main__":
    main()