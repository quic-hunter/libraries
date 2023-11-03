#!/bin/sh
echo "Sleep to wait for servers to start"
sleep 15s
echo "Starting scanner script"
cd /scanners/

mkdir /output
mkdir /output/zmap
mkdir /output/tshark

{%- if tshark.enable %}
echo "Starting paket capture..."
tshark -q -i eth0 -w /output/tshark/capture.pcapng &
sleep 3s
{%- endif %}

echo "Starting scans"

{%- if zmap.enable %}
echo "Starting ZMap..."

{%- if zmap.filemode %}
./zmap -q -M udp -p"443" --output-module="csv" -G "ff:ff:ff:ff:ff:ff" \
-f "saddr,daddr,ipid,ttl,sport,dport,classification,repeat,cooldown,timestamp_ts,timestamp_us,data,success" -o {{ zmap.output }} \
--probe-args="file:{{ zmap.file }}" "{{ zmap.prefix }}96/27"
{%- else %}
./zmap -q -M quic_initial -p"443" --output-module="csv" -G "ff:ff:ff:ff:ff:ff" \
-f "saddr,classification,success,versions" -o {{ zmap.output }} \
--probe-args="padding:1200" "{{ zmap.prefix }}96/27"
{%- endif %}
{%- endif %}

{%- if qscanner.enable %}

echo "Starting QScanner..."
./qscanner -input {{ qscanner.input }} -output {{ qscanner.output }} -qlog \
-keylog -bucket-size 1 
{%- endif %}

echo "Sleep to wait before quitting"
sleep 2s
echo "Scanning container done."
