#!/bin/bash
# Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

if [[ $# -ne 5 ]]
then
	echo "Usage: $0 remote_path lib_dir conf_dir log_dir log_name"
	exit 1
fi

REMOTE_PATH=$1
LIB_DIR=$2
CONF_DIR=$3
LOG_DIR=$4
LOG_NAME=$5

echo "Session Establishment benchmark"
export LD_LIBRARY_PATH="${LIB_DIR}"

mkdir -p "${LOG_DIR}"

# Start the service
export VSOMEIP_APPLICATION_NAME=bench_session_establishment_service
export VSOMEIP_CONFIGURATION="${CONF_DIR}/bench_session_establishment_service.json"
echo "> Starting the service..."
./bench_session_establishment_service 2>> ${LOG_DIR}/bench_session_establishment_service_stderr &
SERVICE_PID=$!
sleep 2;

echo "> Starting the remote client..."
REMOTE_COMMAND="${REMOTE_PATH}/bench_session_establishment_slave.sh ${REMOTE_PATH} ${LIB_DIR} ${CONF_DIR} ${LOG_DIR} ${LOG_NAME}"
ssh 10.0.1.185 "${REMOTE_COMMAND} </dev/null >/dev/null 2>&1 &"

# Wait until service is finished
# The client remotely shuts down the service if he has successfully transmitted
# all the packets with different payloads.
wait ${SERVICE_PID}
echo "> Service terminated..."
