import pandas
import argparse
from tlstp_backend import parse_target

classification_lookup = {}

# list of known permutations
permutation_list = {
    "QUICHE": [["51", "43"], set(["0x0", "0x2", "0x3", "0x4", "0x6", "0x7", "0x8", "0xf"])],
    "AKAMAI": [["43", "51"], set(["0x0", "0x2", "0x3", "0x4", "0x6", "0x7", "0x8", "0xf"])],
    "quant":  [["43", "51"], set(["0x0", "0x2", "0x3", "0x4", "0x6", "0x8", "0xf"])],
    "neqo":   [["51", "43"], set(["0x0", "0x6", "0x4", "0xf", "0x8", "0x7"])],
}

# list of known fingerprints
classification_list= {
        "s2n-quic#1":                  "43-51_0x4-0x6-0x7-0x8-0x0-0xf",
        "s2n-quic#2":                  "51-43_0x4-0x6-0x7-0x8-0x0-0xf",

            "lsquic":              "51-43_0x4-0x6-0x7-0x8-0x0-0xf-0x2",
            "ngtcp2":              "43-51_0x0-0x2-0xf-0x6-0x7-0x4-0x8",
             "xquic":              "43-51_0x0-0x3-0x4-0x6-0x7-0x8-0xf",
       "haskellquic":              "51-43_0x0-0x3-0x4-0x6-0x7-0x8-0xf",

           "haproxy":          "43-51_0x0-0x2-0xf-0x3-0x4-0x6-0x7-0x8",
             "quinn":          "51-43_0x3-0x4-0x6-0x7-0x8-0x2-0x0-0xf",

           "quic-go":      "43-51_0x6-0x7-0x4-0x8-0x3-0xb-0x2-0x0-0xf",
          "picoquic":      "43-51_0x4-0x8-0x3-0x6-0x7-0xb-0xf-0x0-0x2",

            "quicly":      "43-51_0x3-0x6-0x7-0x4-0x0-0xf-0x2-0x8-0xa",
             "mvfst":      "43-51_0x0-0x6-0x7-0x4-0x8-0xa-0x3-0x2-0xf",
            "quiche":      "51-43_0x0-0x3-0x4-0x6-0x7-0x8-0xa-0xb-0xf",
           "aioquic":      "43-51_0x0-0x2-0x4-0x6-0x7-0x8-0xa-0xb-0xf",

           "nginx#1":  "51-43_0x4-0x8-0x6-0x7-0x3-0xb-0xa-0x0-0xf-0x2",
           "nginx#2":  "43-51_0x4-0x8-0x6-0x7-0x3-0xb-0xa-0x0-0xf-0x2",

            "msquic":  "43-51_0x0-0x2-0x3-0x4-0x6-0x7-0x8-0xa-0xb-0xf", 
}

# classifies a target row and returns
# [targetid, address, port, hostname, fingerprint, result]
def classify(row):
    parsed = parse_target(row)
    fingerprint = "-".join(parsed[0]) + "_" + "-".join(parsed[1])

    matches = []
    for impl, data in permutation_list.items():
        if data[0] == parsed[0] and data[1] == set(parsed[1]):
            matches.append(impl)
    permutation = "|".join(matches)

    global classification_lookup
    classification = classification_lookup.get(fingerprint, "")

    if permutation == "":
        result = classification
    elif classification == "":
        result = permutation + "#permutation"
    else:
        result = f"collision:{classification}/{permutation}"

    return [row["targetid"], row["address"], row["port"], row["hostname"], fingerprint, result]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input",required=True, help="tls shared config from the qscanner containing TLS extensions and QUIC transport parameter for successfully scanned targets")
    parser.add_argument("-o", "--output", required=True, help="output file")
    parser.add_argument("-c", "--collision", required=True, help="file to store collisions between libraries that randomize the order and others")
    args = parser.parse_args()

    # reverse classification mapping and handle duplicates
    global classification_lookup 
    for impl, data in classification_list.items():
        if data in classification_lookup:
            classification_lookup[data] = classification_lookup[data] + "|" + impl
        else:
            classification_lookup[data] = impl

    types = {"targetid":"int","address":"str","port":"int","hostname":"str","protocol":"int","ciphersuite":"int","keyShareGroup":"int",
                "serverExtensions":"str","serverEncryptedExtensions":"str","serverCertRequestExtensions":"str",
                "helloRetryRequestExtensions":"str","certificateExtensions":"str","certificateHashes":"str"}
    columns = ["targetid", "address", "port", "hostname", "serverExtensions", "serverEncryptedExtensions"]


    # read input
    iterative_reader = pandas.read_csv(args.input, dtype=types, iterator=True, chunksize=1000000)
    classified = pandas.concat([(it.apply(lambda x: classify(x), axis=1, result_type="expand")) for it in iterative_reader])

    classified.columns = ["targetid", "address", "port", "hostname", "fingerprint", "classification-tlstp"]

    # save output
    classified.to_csv(args.output, index=False)

    # filter and save collisions
    collisions = classified[classified["classification-tlstp"].str.startswith("collision:")]
    collisions.to_csv(args.collision, index=False)


if __name__ == "__main__":
    main()
