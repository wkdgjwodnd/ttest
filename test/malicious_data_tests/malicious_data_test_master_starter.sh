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

export VSOMEIP_CONFIGURATION=malicious_data_test_master.json
# start daemon
../daemon/./vsomeipd &
PID_VSOMEIPD=$!
# Start the services
./malicious_data_test_service &
PID_SERIVCE=$!

sleep 1

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "Waiting for 5s"
    sleep 5
    echo "starting offer test on slave LXC offer_test_external_slave_starter.sh"
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip/test; ./malicious_data_test_msg_sender 192.168.31.132 10.0.1.204\"" &
    echo "remote ssh pid: $!"
elif [ ! -z "$USE_DOCKER" ]; then
    docker run --name otems --cap-add NET_ADMIN $DOCKER_IMAGE sh -c "route add -net 224.0.0.0/4 dev eth0 && cd $DOCKER_TESTS && sleep 10; ./malicious_data_test_msg_sender 192.168.31.132 10.0.1.204" &
else
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** malicious_data_test_msg_sender 192.168.31.132 10.0.1.204
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** malicious_data_test_master.json to your personal setup.
*******************************************************************************
*******************************************************************************
End-of-message
fi

# Wait until all clients and services are finished
for job in $PID_SERIVCE
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

# Check if everything went well
exit $FAIL
