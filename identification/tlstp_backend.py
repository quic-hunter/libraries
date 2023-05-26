import base64
import json

# list of all used TLS server extensions and whether they should be used with value
lookup_extensions = {
    51: False, #   key_share
    43: False, #   supported_versions
}

# list of all used transport parameters and whether they should be used with value
# from https://datatracker.ietf.org/doc/html/rfc9000#section-22.3
lookup_transport_parameters = {
    "0x0": False,   #   original_destination_connection_id	
   # "0x1": False,  #	max_idle_timeout	
    "0x2": False,   #   stateless_reset_token	
    "0x3": False,   #	max_udp_payload_size	
    "0x4": False,   #	initial_max_data	
   # "0x5": False,  #	initial_max_stream_data_bidi_local	
    "0x6": False,   #	initial_max_stream_data_bidi_remote	
    "0x7": False,   #	initial_max_stream_data_uni	
    "0x8": False,   #	initial_max_streams_bidi	
   # "0x9": False,  #	initial_max_streams_uni	
    "0xa": False,   #	ack_delay_exponent	
    "0xb": False,   #	max_ack_delay	
   # "0xc": False,  #	disable_active_migration	
    "0xd": False,   #	preferred_address	
   # "0xe": False,  #	active_connection_id_limit	
    "0xf": False,   #	initial_source_connection_id	
   # "0x10": False, #	retry_source_connection_id	
}

# extracts the classification for a target
# returns [server extensions, encrypted extensions, transport parameters]
def parse_target(row):
    extensions = json.loads(row["serverExtensions"])
    encryptedExtensions = json.loads(row["serverEncryptedExtensions"])
    res_extensions = []
    res_encExtensions = []

    for i in extensions:
        ext = i[0]
        if ext in lookup_extensions:
            if lookup_extensions[ext]:
                res_extensions.append(str(ext) + "=" + i[1])
            else:
                res_extensions.append(str(ext))
    
    quic_TP = ""

    for i in encryptedExtensions:
        ext = i[0]
        if ext == 57 or ext == 65445:
            quic_TP = i[1]
    
    res_TP = []
    if quic_TP != "":
        res_TP = parse_quic_transport_parameters(quic_TP)
    
    return [res_extensions, res_TP]

# parses the passed QUIC transport parameters RAW data
def parse_quic_transport_parameters(raw: str):
    data = base64.standard_b64decode(raw + "==")

    res = []
    index = 0
    while True:
        param = parse_single_parameter(data, index)

        if param[0] in lookup_transport_parameters:
            if lookup_transport_parameters[param[0]]:
                res.append(param[0] + "=" + param[1].hex())
            else:
                res.append(param[0])

        index = param[2]
        if index >= len(data):
            break

    return res

# parses a single transport parameter
# returns [type, value, next_start]
def parse_single_parameter(data: bytes, start):
    index = start

    type_ret = parse_quic_varint(data, index)
    type = hex(type_ret[0])
    index = type_ret[1]

    len_ret = parse_quic_varint(data, index)
    length = len_ret[0]
    index = len_ret[1]
    
    begin = index
    end_excl = begin + length

    return [type, data[begin:end_excl], end_excl]

# parses a single variable int in QUIC format
# https://datatracker.ietf.org/doc/html/rfc9000#name-variable-length-integer-enc
# returns [value, next_start]
def parse_quic_varint(data_raw: bytes, start):
    data = bytearray(data_raw)
    leading_bits = data[start] & 0b11000000
    data[start] = data[start] & 0b00111111
    if leading_bits == 0b00000000:
        val = data[start]
        return [val, start + 1]
    elif leading_bits == 0b01000000:
        val = int.from_bytes(data[start:(start + 2)], byteorder="big", signed=False)
        return [val, start + 2]
    elif leading_bits == 0b10000000:
        val = int.from_bytes(data[start:(start + 4)], byteorder="big", signed=False)
        return [val, start + 4]
    elif leading_bits == 0b11000000:
        val = int.from_bytes(data[start:(start + 8)], byteorder="big", signed=False)
        return [val, start + 8]

