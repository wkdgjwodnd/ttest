#!/bin/bash
# Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

if [[ $# -ne 8 ]]
then
	echo "Usage: $0 remote_path lib_dir conf_dir log_dir log_name transfer_size payload_size_udp payload_size_tcp"
	exit 1
fi

REMOTE_PATH=$1
LIB_DIR=$2
CONF_DIR=$3
LOG_DIR=$4
LOG_NAME=$5
TRANSFER_SIZE_MB=$6
TRANSFER_SIZE=$((TRANSFER_SIZE_MB*1024*1024))
PAYLOAD_SIZE_UDP=$7
PAYLOAD_SIZE_TCP=$8

echo "Throughput benchmark --- Transfer size: ${TRANSFER_SIZE_MB}MB"
export LD_LIBRARY_PATH="${LIB_DIR}"

mkdir -p "${LOG_DIR}"

# Start the service
export VSOMEIP_APPLICATION_NAME=bench_throughput_publisher
export VSOMEIP_CONFIGURATION="${CONF_DIR}/bench_throughput_publisher.json"
echo "> Starting the service..."
./bench_throughput_publisher --transfer-size ${TRANSFER_SIZE} --payload-size-udp ${PAYLOAD_SIZE_UDP} --payload-size-tcp ${PAYLOAD_SIZE_TCP} \
    > ${LOG_DIR}/throughput_${LOG_NAME} \
    2>> ${LOG_DIR}/bench_throughput_publisher_stderr &
SERVICE_PID=$!
sleep 1;

echo "> Starting the remote client..."
REMOTE_COMMAND="${REMOTE_PATH}/bench_throughput_slave.sh ${REMOTE_PATH} ${LIB_DIR} ${CONF_DIR} ${LOG_DIR} ${TRANSFER_SIZE} ${PAYLOAD_SIZE_UDP} ${PAYLOAD_SIZE_TCP}"
ssh 10.0.1.185 "${REMOTE_COMMAND} </dev/null >/dev/null 2>&1 &"

# Wait until service is finished
# The client remotely shuts down the service if he has successfully transmitted
# all the packets with different payloads.
wait ${SERVICE_PID}
echo "> Service terminated..."
