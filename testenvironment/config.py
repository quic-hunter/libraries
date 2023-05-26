# All configuration of parameters for the scan is done in this file.

# Notes about this test run (optional)
"""
E.g.: this run is trying to force a Version Negotiation
"""

# This will setup/generate everything but stop right before starting the containers
# to inspect the generated input files
PARAM_DRYRUN = False

# Timeout in seconds after which docker compose will be stopped
PARAM_TIMEOUT = 180

# The interop testcase to use
PARAM_SERVER_TESTCASE = "http3"
#PARAM_SERVER_TESTCASE = "handshake"

# The QUIC version the servers should use
# Note: this does not seem to influence server behaviour by now
PARAM_SERVER_QUICVERSION = "0x1"

# The server parameter field
# Note: what are possible parameters here?
PARAM_SERVER_PARAMS = ""

# Enable/Disable each scanner
PARAM_SCANNER_ZMAP_ENABLE = True 
PARAM_SCANNER_QSCANNER_ENABLE = True

# The SNI to use by the scanners
PARAM_SCANNER_SNI = "server"

# Enable paket capture in the container using tshark
PARAM_PAKETCAPTURE_ENABLE = True

# Enable if ZMap should be run with UDP module to send a specific input file
# The file needs to be available in the scanners/ folder
PARAM_SCANNER_ZMAP_FILEMODE = True
PARAM_SCANNER_ZMAP_FILE = "initial_qscanner_1a1a1a1a.pkt"

# The IP prefix used in the test environment
# (i.e. "193.167.100." means that the first server uses 193.167.100.100)
# ZMap will scan the /27 subnet (i.e. 193.167.100.96/27); the scanners run on 193.167.100.90
#
# If you have already run this script on this machine with a different subnet, you have to
# remove the network (docker network rm scan_network) first (otherwise you will run into errors).
#
# lsquic was not able to start unless it uses IP 193.167.100.100. Therefore, changing the subnet
# is going to prevent lsquic from starting.
PARAM_NETWORK_PREFIX = "193.167.100."

# The folder in which the scan folders will be created (relative)
PARAM_FOLDER_RESULTS = "results"

# The folder the servers should serve (relative)
PARAM_FOLDER_WWW = "www"

# Whether to copy resources to scan result for reevaluation
PARAM_COPY_CERTIFICATE = True
PARAM_COPY_SCANNER = True
PARAM_COPY_CONFIG = True
PARAM_COPY_COMPOSE = True
PARAM_COPY_SERVERLOGS = True

# The servers to run and whether each of them is enabled
# Servers can be found here:
#   https://github.com/marten-seemann/quic-interop-runner/blob/master/implementations.json
PARAM_SERVERS = {
    "quic-go": {
        "enabled": True,
        "image": "martenseemann/quic-go-interop:latest",
    },
    "ngtcp2": {
        "enabled": True,
        "image": "ghcr.io/ngtcp2/ngtcp2-interop:latest",
    },
    "quant": { # no http3
        "enabled": False,
        "image": "ntap/quant:interop",
    },
    "mvfst": {
        "enabled": True,
        "image": "lnicco/mvfst-qns:latest",
    },
    "quiche": {
        "enabled": True,
        "image": "cloudflare/quiche-qns:latest",
    },
    "kwik": {
        "enabled": True,
        "image": "peterdoornbosch/kwik_n_flupke-interop",
    },
    "picoquic": {
        "enabled": True,
        "image": "privateoctopus/picoquic:latest",
    },
    "aioquic": {
        "enabled": True,
        "image": "aiortc/aioquic-qns:latest",
    },
    "neqo": {
        "enabled": True,
        "image": "neqoquic/neqo-qns:latest",
    },
    "nginx": {
        "enabled": True,
        "image": "public.ecr.aws/nginx/nginx-quic-qns:latest",
    },
    "msquic": { # no handshake possible http3
        "enabled": False,
        "image": "ghcr.io/microsoft/msquic/qns:main",
    },
    "xquic": {
        "enabled": True,
        "image": "kulsk/xquic:latest",
    },
    "lsquic": { # Only runs on specific IP
        "enabled": True,
        "image": "litespeedtech/lsquic-qir:latest",
    },
    "haproxy": {
        "enabled": True,
        "image": "haproxytech/haproxy-qns:latest",
    },
    "quinn": {
        "enabled": True,
        "image": "stammw/quinn-interop:latest",
    },
    "s2n-quic": {
        "enabled": True,
        "image": "public.ecr.aws/s2n/s2n-quic-qns:latest",
    }
}
