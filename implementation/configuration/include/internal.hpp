// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_INTERNAL_HPP
#define VSOMEIP_INTERNAL_HPP

#include <cstdint>
#include <limits>
#include <vsomeip/primitive_types.hpp>
#include "../../crypto/common/include/algorithms.hpp"

#define VSOMEIP_ENV_APPLICATION_NAME            "VSOMEIP_APPLICATION_NAME"
#define VSOMEIP_ENV_CONFIGURATION               "VSOMEIP_CONFIGURATION"
#define VSOMEIP_ENV_CONFIGURATION_MODULE        "VSOMEIP_CONFIGURATION_MODULE"
#define VSOMEIP_ENV_MANDATORY_CONFIGURATION_FILES "VSOMEIP_MANDATORY_CONFIGURATION_FILES"
#define VSOMEIP_ENV_LOAD_PLUGINS                "VSOMEIP_LOAD_PLUGINS"
#define VSOMEIP_ENV_CLIENTSIDELOGGING           "VSOMEIP_CLIENTSIDELOGGING"
#define VSOMEIP_ENV_DEBUG_CONFIGURATION         "VSOMEIP_DEBUG_CONFIGURATION"

#define VSOMEIP_DEFAULT_CONFIGURATION_FILE      "/etc/vsomeip.json"
#define VSOMEIP_LOCAL_CONFIGURATION_FILE        "./vsomeip.json"
#define VSOMEIP_MANDATORY_CONFIGURATION_FILES   "vsomeip_std.json,vsomeip_app.json,vsomeip_plc.json,vsomeip_log.json,vsomeip_security.json"

#define VSOMEIP_DEFAULT_CONFIGURATION_FOLDER    "/etc/vsomeip"
#define VSOMEIP_DEBUG_CONFIGURATION_FOLDER      "/var/opt/public/sin/vsomeip/"
#define VSOMEIP_LOCAL_CONFIGURATION_FOLDER      "./vsomeip"

#define VSOMEIP_BASE_PATH                       "/tmp/"

#ifdef WIN32
#define VSOMEIP_CFG_LIBRARY                     "vsomeip-cfg.dll"
#else
#define VSOMEIP_CFG_LIBRARY                     "libvsomeip-cfg.so.2"
#endif

#ifdef WIN32
#define VSOMEIP_SD_LIBRARY                      "vsomeip-sd.dll"
#else
#define VSOMEIP_SD_LIBRARY                      "libvsomeip-sd.so.2"
#endif

#define VSOMEIP_ROUTING                         "vsomeipd"
#define VSOMEIP_ROUTING_CLIENT                  0
#define VSOMEIP_ROUTING_INFO_SIZE_INIT          256

#ifdef _WIN32
#define VSOMEIP_INTERNAL_BASE_PORT              51234
#define __func__ __FUNCTION__
#endif

#define VSOMEIP_UNICAST_ADDRESS                 "127.0.0.1"

#define VSOMEIP_DEFAULT_CONNECT_TIMEOUT         100
#define VSOMEIP_MAX_CONNECT_TIMEOUT             1600
#define VSOMEIP_DEFAULT_FLUSH_TIMEOUT           1000

#define VSOMEIP_DEFAULT_WATCHDOG_TIMEOUT        5000
#define VSOMEIP_DEFAULT_MAX_MISSING_PONGS       3

#define VSOMEIP_IO_THREAD_COUNT                 2

#define VSOMEIP_MAX_DISPATCHERS                 10
#define VSOMEIP_MAX_DISPATCH_TIME               100

#define VSOMEIP_MAX_DESERIALIZER                5

#define VSOMEIP_REQUEST_DEBOUNCE_TIME           10

#define VSOMEIP_COMMAND_HEADER_SIZE             7

#define VSOMEIP_COMMAND_TYPE_POS                0
#define VSOMEIP_COMMAND_CLIENT_POS              1
#define VSOMEIP_COMMAND_SIZE_POS_MIN            3
#define VSOMEIP_COMMAND_SIZE_POS_MAX            6
#define VSOMEIP_COMMAND_PAYLOAD_POS             7

#define VSOMEIP_REGISTER_APPLICATION            0x00
#define VSOMEIP_DEREGISTER_APPLICATION          0x01
#define VSOMEIP_APPLICATION_LOST                0x02
#define VSOMEIP_ROUTING_INFO                    0x03
#define VSOMEIP_REGISTERED_ACK                  0x04

#define VSOMEIP_PING                            0x0E
#define VSOMEIP_PONG                            0x0F

#define VSOMEIP_OFFER_SERVICE                   0x10
#define VSOMEIP_STOP_OFFER_SERVICE              0x11
#define VSOMEIP_SUBSCRIBE                       0x12
#define VSOMEIP_UNSUBSCRIBE                     0x13
#define VSOMEIP_REQUEST_SERVICE                 0x14
#define VSOMEIP_RELEASE_SERVICE                 0x15
#define VSOMEIP_SUBSCRIBE_NACK                  0x16
#define VSOMEIP_SUBSCRIBE_ACK                   0x17

#define VSOMEIP_SEND                            0x18
#define VSOMEIP_NOTIFY                          0x19
#define VSOMEIP_NOTIFY_ONE                      0x1A

#define VSOMEIP_REGISTER_EVENT                  0x1B
#define VSOMEIP_UNREGISTER_EVENT                0x1C
#define VSOMEIP_ID_RESPONSE                     0x1D
#define VSOMEIP_ID_REQUEST                      0x1E
#define VSOMEIP_OFFERED_SERVICES_REQUEST        0x1F
#define VSOMEIP_OFFERED_SERVICES_RESPONSE       0x20
#define VSOMEIP_UNSUBSCRIBE_ACK                 0x21

#define VSOMEIP_SEND_COMMAND_SIZE               14
#define VSOMEIP_SEND_COMMAND_INSTANCE_POS_MIN   7
#define VSOMEIP_SEND_COMMAND_INSTANCE_POS_MAX   8
#define VSOMEIP_SEND_COMMAND_FLUSH_POS          9
#define VSOMEIP_SEND_COMMAND_RELIABLE_POS       10
#define VSOMEIP_SEND_COMMAND_VALID_CRC_POS      11
#define VSOMEIP_SEND_COMMAND_DST_CLIENT_POS_MIN 12
#define VSOMEIP_SEND_COMMAND_DST_CLIENT_POS_MAX 13
#define VSOMEIP_SEND_COMMAND_PAYLOAD_POS        14

#define VSOMEIP_OFFER_SERVICE_COMMAND_SIZE      16
#define VSOMEIP_REQUEST_SERVICE_COMMAND_SIZE    17
#define VSOMEIP_RELEASE_SERVICE_COMMAND_SIZE    11
#define VSOMEIP_STOP_OFFER_SERVICE_COMMAND_SIZE 16
#define VSOMEIP_SUBSCRIBE_COMMAND_SIZE          19
#define VSOMEIP_SUBSCRIBE_ACK_COMMAND_SIZE      19
#define VSOMEIP_SUBSCRIBE_NACK_COMMAND_SIZE     19
#define VSOMEIP_UNSUBSCRIBE_COMMAND_SIZE        17
#define VSOMEIP_UNSUBSCRIBE_ACK_COMMAND_SIZE    15
#define VSOMEIP_REGISTER_EVENT_COMMAND_SIZE     15
#define VSOMEIP_UNREGISTER_EVENT_COMMAND_SIZE   14
#define VSOMEIP_ID_RESPONSE_COMMAND_SIZE        12
#define VSOMEIP_ID_REQUEST_COMMAND_SIZE         13
#define VSOMEIP_OFFERED_SERVICES_COMMAND_SIZE    8

#ifndef _WIN32
#include <pthread.h>
#endif

#define VSOMEIP_DATA_ID                         0x677D
#define VSOMEIP_DIAGNOSIS_ADDRESS               0x00

#define VSOMEIP_DEFAULT_SHM_PERMISSION          0666
#define VSOMEIP_DEFAULT_UMASK_LOCAL_ENDPOINTS   0000

#define VSOMEIP_DEFAULT_CERTIFICATES_PATH       "/var/vsomeipd/certificates"
#define VSOMEIP_DEFAULT_SESSION_ESTABLISHMENT_MAX_REPETITIONS            3
#define VSOMEIP_DEFAULT_SESSION_ESTABLISHMENT_REPETITIONS_DELAY       1000
#define VSOMEIP_DEFAULT_SESSION_ESTABLISHMENT_REPETITIONS_DELAY_RATIO 2.0f

#define VSOMEIP_DEFAULT_ALGORITHM_NOSEC            crypto_algorithm::CA_NULL
#define VSOMEIP_DEFAULT_ALGORITHM_AUTHENTICATION   crypto_algorithm::CA_CHACHA20_POLY1305_256
#define VSOMEIP_DEFAULT_ALGORITHM_CONFIDENTIALITY  crypto_algorithm::CA_CHACHA20_POLY1305_256

#define VSOMEIP_ROUTING_READY_MESSAGE           "SOME/IP routing ready."

namespace vsomeip {

typedef enum {
    RIE_ADD_CLIENT = 0x0,
    RIE_ADD_SERVICE_INSTANCE = 0x1,
    RIE_DEL_SERVICE_INSTANCE = 0x2,
    RIE_DEL_CLIENT = 0x3,
} routing_info_entry_e;

struct service_data_t {
    service_t service_;
    instance_t instance_;
    major_version_t major_;
    minor_version_t minor_;
    bool use_exclusive_proxy_; // only used for requests!

    bool operator<(const service_data_t &_other) const {
        return (service_ < _other.service_
                || (service_ == _other.service_
                    && instance_ < _other.instance_));
    }
};

typedef enum {
    SUBSCRIPTION_ACKNOWLEDGED,
    SUBSCRIPTION_NOT_ACKNOWLEDGED,
    IS_SUBSCRIBING
} subscription_state_e;

struct configuration_data_t {
#ifndef _WIN32
    volatile char initialized_;
    pthread_mutex_t mutex_;
    pid_t pid_;
#endif
    unsigned short client_base_;
    unsigned short max_clients_;
    int max_used_client_ids_index_;
    unsigned short max_assigned_client_id_without_diagnosis_;
    unsigned short routing_manager_host_;
    // array of used client ids here, pointer to it is kept in utility class
};

const std::uint32_t MESSAGE_SIZE_UNLIMITED = (std::numeric_limits<std::uint32_t>::max)();

const std::uint32_t QUEUE_SIZE_UNLIMITED = (std::numeric_limits<std::uint32_t>::max)();


} // namespace vsomeip

#endif // VSOMEIP_INTERNAL_HPP
