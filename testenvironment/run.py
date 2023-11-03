import os
import datetime
import shutil
import subprocess
import signal
from io import TextIOWrapper

from jinja2 import Environment, FileSystemLoader

import config

resultFolder = ""
serverNames = []
jinja_env = Environment(loader=FileSystemLoader("templates/"))

# Runs the complete process
def run():
    if not setupFolder():
        print("Error during folder setup... Aborting.")
        return
    print("Finished folder setup.")

    if not createInputFiles():
        print("Error during input files creation... Aborting.")
        return
    print("Finished input files setup.")

    if not setupScannerScript():
        print("Error during scanner script creation... Aborting.")
        return
    print("Finished scanner script setup.")

    if config.PARAM_DRYRUN:
        print(">>> DRY RUN MODE: Stopping here.")
        print(">>> (set PARAM_DRYRUN=False to disable)")
        return

    if not runScans():
        print("The script will continue to try to copy the outputs. You may encounter errors...")
    else:
        print("Finished scans.")

    if not fetchOutput():
        print("Error during output copying... Aborting.")
        return
    print("Finished container outputs fetching.")


# Create output folders and copy certificates and scanners
def setupFolder():
    if not os.path.exists(config.PARAM_FOLDER_RESULTS):
        os.makedirs(config.PARAM_FOLDER_RESULTS)
        print("Results folder did not exist... Created.")

    # create folder for this scan
    global resultFolder
    resultFolder = config.PARAM_FOLDER_RESULTS + "/scan_" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if os.path.exists(resultFolder):
        print("Scan result folder already exists... Aborting.")
        return False

    os.makedirs(resultFolder)
    os.makedirs(resultFolder + "/misc")
    os.makedirs(resultFolder + "/input")

    if not os.path.exists(config.PARAM_FOLDER_WWW):
        os.makedirs(config.PARAM_FOLDER_WWW)
        print("WWW folder did not exist... Created.")
    
    if config.PARAM_COPY_CONFIG:
        shutil.copy2("config.py", resultFolder + "/misc")
    
    return setupCertificates() and setupScanners()

# Check if certificates are available and copy if desired
def setupCertificates():
    if (not os.path.isfile("certificate/certs/priv.key")) or (not os.path.isfile("certificate/certs/cert.pem")):
        print("Certificate or private key not found in directory certificate/certs/.")
        return False

    if config.PARAM_COPY_CERTIFICATE:
        os.makedirs(resultFolder + "/misc/certificate")
        shutil.copy2("certificate/certs/priv.key", resultFolder + "/misc/certificate")
        shutil.copy2("certificate/certs/cert.pem", resultFolder + "/misc/certificate")

    return True

# Check if scanners are available and copy if desired
def setupScanners():
    if config.PARAM_COPY_SCANNER:
        os.makedirs(resultFolder + "/misc/scanners")

    if config.PARAM_SCANNER_ZMAP_ENABLE:
        if not os.path.isfile("scanners/zmap"):
            print("ZMap is enabled, but binary is missing in directory scanners... Aborting.")
            return False
        if config.PARAM_COPY_SCANNER:
            shutil.copy2("scanners/zmap", resultFolder + "/misc/scanners")
        
        # Check for file mode
        if config.PARAM_SCANNER_ZMAP_FILEMODE:
            if not os.path.isfile("scanners/" + config.PARAM_SCANNER_ZMAP_FILE):
                print(f"You specified ZMap file '{config.PARAM_SCANNER_ZMAP_FILE}', but it does not exist... Aborting.")
                return False
            if config.PARAM_SCANNER_ZMAP_FILE in ["zmap", "qscanner", "script.sh", "input_qscanner.csv"]:
                print(f"The ZMap file '{config.PARAM_SCANNER_ZMAP_FILE}' is a reserved name in this environment... Aborting.")
                return False
            shutil.copy2("scanners/" + config.PARAM_SCANNER_ZMAP_FILE, resultFolder + "/input/")

    if config.PARAM_SCANNER_QSCANNER_ENABLE:
        if not os.path.isfile("scanners/qscanner"):
            print("QScanner is enabled, but binary is missing in directory scanners... Aborting.")
            return False
        if config.PARAM_COPY_SCANNER:
            shutil.copy2("scanners/qscanner", resultFolder + "/misc/scanners")
    return True

# Creates docker compose and scanner input files
def createInputFiles():
    context = {}
    
    context["network"] = {
        "subnet": f"{config.PARAM_NETWORK_PREFIX}0/24"
    }

    context["globalserver"] = {
        "www": f"./{config.PARAM_FOLDER_WWW}",
        "certs": "./certificate/certs",
        "params": config.PARAM_SERVER_PARAMS,
        "testcase": config.PARAM_SERVER_TESTCASE,
        "version": config.PARAM_SERVER_QUICVERSION,
        "port": "443"
    }

    # make sure lsquic is the first and gets the first IP address
    servers = list(config.PARAM_SERVERS.keys())
    if "lsquic" in servers:
        servers.remove("lsquic")
        servers.insert(0, "lsquic")

    context["servers"] = []
    index = 100
    for name in servers:
        server = config.PARAM_SERVERS[name]
        if server["enabled"]:
            context["servers"].append(generateServer(str(index), name, server["image"]))
            index += 1

    context["scanner"] = {
        "scanners": "./scanners",
        "input": f"./{resultFolder}/input",
        "sni": config.PARAM_SCANNER_SNI,
        "ip": f"{config.PARAM_NETWORK_PREFIX}90"
    }

    return writeFilesOfContext(context)

# Generates context of a single server target
def generateServer(index: str, name: str, image: str):
    server = {
        "fullname": f"server_{index}_{name}",
        "name": name,
        "image": image,
        "ip": config.PARAM_NETWORK_PREFIX + index
    }

    serverNames.append(server["fullname"])
    return server

# Writes the scanning context to all configuration files
def writeFilesOfContext(context: dict):
    template_compose = jinja_env.get_template("docker-compose.yml")
    with open("docker-compose.yml", mode="w") as output:
        output.write(template_compose.render(context))
    
    if config.PARAM_SCANNER_QSCANNER_ENABLE:
        template_qscanner = jinja_env.get_template("input_qscanner.csv")
        with open(resultFolder + "/input/input_qscanner.csv", mode="w") as output:
            output.write(template_qscanner.render(context))

    template_mapping = jinja_env.get_template("server_mapping.csv")
    with open(resultFolder + "/server_mapping.csv", mode="w") as output:
        output.write(template_mapping.render(context))

    if config.PARAM_COPY_COMPOSE:
        shutil.copy2("docker-compose.yml", resultFolder + "/misc")
    
    return True


# Generates the script the scanning container will execute
def setupScannerScript():
    context = {}

    context["tshark"] = {
        "enable": config.PARAM_PAKETCAPTURE_ENABLE
    }

    context["zmap"] = {
        "enable": config.PARAM_SCANNER_ZMAP_ENABLE,
        "filemode": config.PARAM_SCANNER_ZMAP_FILEMODE,
        "file": f"/input/{config.PARAM_SCANNER_ZMAP_FILE}",
        "output": "/output/zmap/output_zmap.csv",
        "prefix": config.PARAM_NETWORK_PREFIX
    }

    context["qscanner"] = {
        "enable": config.PARAM_SCANNER_QSCANNER_ENABLE,
        "input": "/input/input_qscanner.csv",
        "output": "/output/qscanner",
    }

    template_script = jinja_env.get_template("script.sh")
    with open(resultFolder + "/input/script.sh", mode="w") as output:
        output.write(template_script.render(context))

    return True

# Runs the actual scans
def runScans():
    logFile = open(resultFolder + "/compose_out.log", "w")

    print("Starting docker compose...")
    signal.signal(signal.SIGALRM, raiseTimeout)
    signal.alarm(config.PARAM_TIMEOUT) # Generate a timeout if still running

    process = subprocess.Popen(["docker-compose", "up", "-V",
            "--force-recreate", "--remove-orphans"], stdout=subprocess.PIPE, bufsize=1, text=True)

    # read process output line by line
    scannerSuccess = False
    earlyExits = []

    try:
        for line in process.stdout:
            logFile.write(line)
            if line.startswith("scanner exited with code 0"):
                scannerSuccess = True
                signal.alarm(0) # reset the timeout
                break
            elif "exited with code" in line:
                earlyExits.append(line.rstrip())
    except Exception as exception:
        scannerSuccess = False
        print(exception)     
    
    logFile.close()

    if scannerSuccess and len(earlyExits) == 0:
        print("\t>>> Scanner exited as expected.")
    elif len(earlyExits) != 0:
        print("There were early exits by servers:")
        for server in earlyExits:
            print("\t>", server)

    print("Stopping docker compose...")
    stopProcess = subprocess.run(["docker-compose", "stop"],
                shell=False, stdout=subprocess.PIPE, bufsize=1, text=True, timeout=60)
    process.kill()
    
    if scannerSuccess and len(earlyExits) == 0:
        return True
    
    print("\t>>> THE TESTS DID NOT EXIT AS EXPECTED! ERROR!")
    return False

def raiseTimeout(sigNumber, f):
    raise Exception("TIMEOUT OF THE SCAN HAS EXPIRED! ERROR!")


# Copies the output in the containers to the results folder
def fetchOutput():
    if config.PARAM_SCANNER_ZMAP_ENABLE:
        copyFolder(container="scanner", src="/output/zmap/", dst="/output/zmap/", fileMode=False)

    if config.PARAM_SCANNER_QSCANNER_ENABLE:
        copyFolder(container="scanner", src="/output/qscanner/", dst="/output/qscanner/", fileMode=False)

    if config.PARAM_PAKETCAPTURE_ENABLE:
        copyFolder(container="scanner", src="/output/tshark/capture.pcapng", dst="/output/capture.pcapng", fileMode=True)
    
    if config.PARAM_COPY_SERVERLOGS:
        os.makedirs(resultFolder + "/serverlogs")
        for name in serverNames:
            copyFolder(container=name, src="/logs/", dst=f"/serverlogs/{name}/", fileMode=False)
    
    return True

# Copies a folder from a container to a target destination in the result folder
def copyFolder(container: str, src: str, dst: str, fileMode: bool):
    if not fileMode:
        os.makedirs(resultFolder + dst)
        src = src + "."
    output = subprocess.run(f"docker cp {container}:{src} {resultFolder + dst}",
                text=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if output.returncode != 0:
        print(">> Problem during copying:", output.stdout.rstrip())


# Execute
run()
