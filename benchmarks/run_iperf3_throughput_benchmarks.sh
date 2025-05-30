#!/bin/bash
# Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

if [[ $# -ne 6 ]]
then
	echo "Usage: $0 log_dir log_name iterations transfer_size payload_size_udp payload_size_tcp"
	exit 1
fi

LOG_DIR=$1
LOG_NAME=$2
ITERATIONS=$3
TRANSFER_SIZE=$4
PAYLOAD_SIZE_UDP=$5
PAYLOAD_SIZE_TCP=$6

mkdir -p "${LOG_DIR}"
ssh 10.0.1.185 "mkdir -p ${LOG_DIR} </dev/null >/dev/null 2>&1"

for IDX in `seq 1 ${ITERATIONS}`
do
    LOG_NAME_IDX=${LOG_NAME}_$((${IDX}-1))
    LOG="--json --logfile ${LOG_DIR}/${LOG_NAME_IDX}"
    echo "*** Iteration ${IDX} ***"

    ##### UDP Communication #####
    echo "> Starting the server (UDP)..."
    iperf3 --server --daemon --one-off --interval 0 ${LOG}

    echo "> Starting the remote client (UDP)..."
    REMOTE_COMMAND="sleep 1 && iperf3 --client 10.0.1.204 -b 0 --length ${PAYLOAD_SIZE_UDP} --interval 0 --bytes ${TRANSFER_SIZE}M ${LOG} --get-server-output --udp"
    ssh 10.0.1.185 "${REMOTE_COMMAND} </dev/null >/dev/null 2>&1 &"

    sleep 1


    ##### TCP Communication #####
    echo "> Starting the server (TCP)..."
    iperf3 --server --daemon --one-off --interval 0 ${LOG}

    echo "> Starting the remote client (TCP)..."
    REMOTE_COMMAND="sleep 1 && iperf3 --client 10.0.1.204 -b 0 --length ${PAYLOAD_SIZE_TCP} --interval 0 --bytes ${TRANSFER_SIZE}M ${LOG} --get-server-output"
    ssh 10.0.1.185 "${REMOTE_COMMAND} </dev/null >/dev/null 2>&1 &"

    sleep 1

    echo
done
