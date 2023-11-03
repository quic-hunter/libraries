FROM debian:bullseye 
RUN apt-get update
RUN apt-get install -y build-essential libpcap-dev libgmp3-dev libjson-c-dev libunistring-dev
RUN apt-get clean

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

ADD run.sh /
RUN chmod +x /run.sh

ENTRYPOINT [ "/run.sh" ]
