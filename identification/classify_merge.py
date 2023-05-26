import pandas
import argparse

def detailed_name(alpn: str, tp: str):
    if alpn.split("#")[0] == tp.split("#")[0]:
        return alpn.split("#")[0]
    return alpn + "_" + tp

def short_name(alpn: str, tp: str):
    alpn = alpn.split("#")[0]
    if not tp.startswith("collision:"):
        tp = tp.split("#")[0]
    
    if alpn in tp:
        return alpn
    if alpn == "?" and tp != "?":
        return tp
    if alpn != "?" and tp == "?":
        return alpn
    return alpn + "_" + tp

def combine_fingerprints(row):
    alpn = str(row["classification-alpn"])
    tp = str(row["classification-tlstp"])

    if alpn == "nan" or alpn == "None":
        alpn = "?"
    if tp == "nan" or tp == "None":
        tp = "?"

    return [row["address"], row["hostname"], row["errorMessage"], row["classification-alpn"], row["fingerprint"],
                row["classification-tlstp"], short_name(alpn, tp), detailed_name(alpn, tp)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--alpn",required=True, help="alpn based identification file")
    parser.add_argument("-p", "--parameter", required=True, help="transport parameter based identification file")
    parser.add_argument("-t", "--type", required=True, help="type of join (inner/outer/left/...)")
    parser.add_argument("-o", "--output", required=True, help="output file")
    args = parser.parse_args()

    # read input
    types_alpn = {"targetid": "int", "address": "str", "port": "int", "hostname": "str", "errorMessage": "str", "classification-alpn": "str"}
    types_tlstp = {"targetid": "int", "address": "str", "port": "int", "hostname": "str", "fingerprint": "str", "classification-tlstp": "str"}

    alpn_in = pandas.read_csv(args.alpn, dtype=types_alpn)
    tlstp_in = pandas.read_csv(args.parameter, dtype=types_tlstp)

    # merge classifications and generate common names
    merge = alpn_in.merge(tlstp_in, on=["address", "hostname"], how=args.type)
    classified = merge.apply(lambda x: combine_fingerprints(x), axis=1, result_type="expand")
    classified.columns = ["address", "hostname", "errorMessage", "classification-alpn", "fingerprint",
                    "classification-tlstp", "classification_reduced", "classification_detailed"]

    # save output
    classified.to_csv(args.output, index=False)


if __name__ == "__main__":
    main()