import pandas
import argparse

# list of known error messages
implementation_lookup = {
    "QUICHE":"CRYPTO_ERROR (0x178) (frame type: 0x6): 28:TLS handshake failure (ENCRYPTION_INITIAL) 120: no application protocol",
    "AKAMAI#1":"CRYPTO_ERROR (0x150): 200:TLS handshake failure (ENCRYPTION_INITIAL) 80: internal error",
    "AKAMAI#2":"PROTOCOL_VIOLATION: 28:No known ALPN provided by client",

    "lsquic#1":"CRYPTO_ERROR (0x178): no suitable application protocol",
    "lsquic#2":"CRYPTO_ERROR (0x150): TLS alert 80",

    "quant":"CRYPTO_ERROR (0x178) (frame type: 0x6): PTLS error 120 (NO_APPLICATION_PROTOCOL)",
    "kwik":"CRYPTO_ERROR (0x178): unsupported application protocol: invalid",
    "aioquic":"CRYPTO_ERROR (0x128) (frame type: 0x6): No common ALPN protocols",
    "nginx":"CRYPTO_ERROR (0x178): handshake failed",
    "quinn":"CRYPTO_ERROR (0x178): peer doesn't support any known protocol",
    "mvfst":"CRYPTO_ERROR (0x178) (frame type: 0x1c): fizz::FizzException: Unable to negotiate ALPN, as required by policy. policy=AlpnMode::Required",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input",required=True, help="quic connection info from the qscanner containing error messages")
    parser.add_argument("-o", "--output", required=True, help="output file")
    args = parser.parse_args()

    # reverse mapping and handle duplicates
    classification_lookup = {}
    for server, msg in implementation_lookup.items():
        if msg in classification_lookup:
            classification_lookup[msg] = classification_lookup[msg] + "|" + server
        else:
            classification_lookup[msg] = server

    # generate a DataFrame using the lookup dictionary
    frame_lookup = pandas.DataFrame(list(classification_lookup.items()), columns=["errorMessage", "classification-alpn"])

    # read input
    types = {"targetid":"int","address":"str","port":"int","hostname":"str","scid":"str","dcid":"str",
                "hasRetry":"str","startTime":"int","handshakeTime":"int","closeTime":"int",
                "handshakeDuration":"int","connectionDuration":"int","quicVersion":"str","errorMessage":"str"}
    columns = ["targetid", "address", "port", "hostname", "errorMessage"]

    iterative_reader = pandas.read_csv(args.input, dtype=types, iterator=True, chunksize=1000000)
    frame_merged = pandas.concat([(it.merge(frame_lookup, on="errorMessage", how="left")) for it in iterative_reader])

    # save output
    toSave = frame_merged[["targetid", "address", "port", "hostname", "errorMessage", "classification-alpn"]]
    toSave.to_csv(args.output, index=False)


if __name__ == "__main__":
    main()
