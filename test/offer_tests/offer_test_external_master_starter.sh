#!/bin/bash
# Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Purpose: This script is needed to start the services with
# one command. This is necessary as ctest - which is used to run the
# tests - isn't able to start multiple binaries for one testcase. Therefore
# the testcase simply executes this script. This script then runs the services
# and checks that all exit successfully.

FAIL=0
# Rejecting offer for which there is already a remote offer:
# * start daemon
# * start application which offers service
# * start daemon remotely
# * start same application which offers the same service again remotely
#   -> should be rejected as there is already a service instance
#   running in the network

# Array for client pids
CLIENT_PIDS=()
export VSOMEIP_CONFIGURATION=offer_test_external_master.json
# start daemon
../daemon/./vsomeipd &
PID_VSOMEIPD=$!
# Start the services
./offer_test_service 2 &
PID_SERVICE_TWO=$!
echo "SERVICE_TWO pid $PID_SERVICE_TWO"

./offer_test_client SUBSCRIBE &
CLIENT_PIDS+=($!)
echo "client pid ${CLIENT_PIDS[0]}"

sleep 1

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "Waiting for 5s"
    sleep 5
    echo "starting offer test on slave LXC offer_test_external_slave_starter.sh"
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip/test; ./offer_test_external_slave_starter.sh\"" &
    echo "remote ssh pid: $!"
elif [ ! -z "$USE_DOCKER" ]; then
    docker run --name otems --cap-add NET_ADMIN $DOCKER_IMAGE sh -c "route add -net 224.0.0.0/4 dev eth0 && cd $DOCKER_TESTS && sleep 10; ./offer_test_external_slave_starter.sh" &
else
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** offer_test_external_slave_starter.sh
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** offer_test_external_master.json and
** offer_test_external_slave.json to your personal setup.
*******************************************************************************
*******************************************************************************
End-of-message
fi

# Wait until all clients and services are finished
for job in ${CLIENT_PIDS[*]} $PID_SERVICE_TWO
do
    # Fail gets incremented if a client exits with a non-zero exit code
    echo "waiting for $job"
    wait $job || FAIL=$(($FAIL+1))
done

# kill the services
kill $PID_VSOMEIPD
sleep 1

if [ ! -z "$USE_DOCKER" ]; then
    docker stop otems
    docker rm otems
fi

# wait for slave to finish
for job in $(jobs -p)
do
    # Fail gets incremented if either client or service exit
    # with a non-zero exit code
    echo "[Master] waiting for job $job"
    wait $job || ((FAIL+=1))
done

# Rejecting remote offer for which there is already a local offer
# * start application which offers service
# * send sd message trying to offer the same service instance as already
#   offered locally from a remote host

# Array for client pids
CLIENT_PIDS=()
export VSOMEIP_CONFIGURATION=offer_test_external_master.json
# start daemon
../daemon/./vsomeipd &
PID_VSOMEIPD=$!
# Start the services
./offer_test_service 2 &
PID_SERVICE_TWO=$!

./offer_test_client SUBSCRIBE &
CLIENT_PIDS+=($!)
echo "client pid ${CLIENT_PIDS[0]}"

sleep 1

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "Waiting for 5s"
    sleep 5
    echo "starting offer test on slave LXC offer_test_external_sd_msg_sender"
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip/test; ./offer_test_external_sd_msg_sender $LXC_TEST_MASTER_IP\"" &
    echo "remote ssh job id: $!"
elif [ ! -z "$USE_DOCKER" ]; then
    docker run --name otesms --cap-add NET_ADMIN $DOCKER_IMAGE sh -c "route add -net 224.0.0.0/4 dev eth0 && cd $DOCKER_TESTS && sleep 10; ./offer_test_external_sd_msg_sender $DOCKER_IP" &
else
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** offer_test_external_sd_msg_sender 192.168.31.132
** (pass the correct ip address of your test master)
** from an external host to successfully complete this test.
**
*******************************************************************************
*******************************************************************************
End-of-message
fi

# Wait until all clients and services are finished
for job in ${CLIENT_PIDS[*]} $PID_SERVICE_TWO
do
    # Fail gets incremented if a client exits with a non-zero exit code
    echo "waiting for $job"
    wait $job || FAIL=$(($FAIL+1))
done

# kill the services
kill $PID_VSOMEIPD
sleep 1

if [ ! -z "$USE_DOCKER" ]; then
    docker stop otesms
    docker rm otesms
fi

# wait for slave to finish
for job in $(jobs -p)
do
    # Fail gets incremented if either client or service exit
    # with a non-zero exit code
    echo "[Master] waiting for job $job"
    wait $job || ((FAIL+=1))
done

# Check if everything went well
if [ $FAIL -eq 0 ]
then
    exit 0
else
    exit 1
fi
