#!/bin/bash
# Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

if [[ $# -ne 7 ]]
then
	echo "Usage: $0 dir lib_dir conf_dir log_dir transfer_size payload_size_udp payload_size_tcp"
	exit 1
fi

DIR=$1
LIB_DIR=$2
CONF_DIR=$3
LOG_DIR=$4
TRANSFER_SIZE=$5
PAYLOAD_SIZE_UDP=$6
PAYLOAD_SIZE_TCP=$7

cd "${DIR}"
export LD_LIBRARY_PATH="${LIB_DIR}"

mkdir -p "${LOG_DIR}"

export VSOMEIP_APPLICATION_NAME=bench_throughput_subscriber
export VSOMEIP_CONFIGURATION="${CONF_DIR}/bench_throughput_subscriber.json"

##### UDP Communication #####
./bench_throughput_subscriber --udp --transfer-size ${TRANSFER_SIZE} --payload-size-udp ${PAYLOAD_SIZE_UDP} \
	--payload-size-tcp ${PAYLOAD_SIZE_TCP} --dont-shutdown-service \
	2>> ${LOG_DIR}/bench_throughput_subscriber_stderr

sleep 2

##### TCP Communication #####
./bench_throughput_subscriber --tcp --transfer-size ${TRANSFER_SIZE} --payload-size-udp ${PAYLOAD_SIZE_UDP} \
	--payload-size-tcp ${PAYLOAD_SIZE_TCP} \
	2>> ${LOG_DIR}/bench_throughput_subscriber_stderr
