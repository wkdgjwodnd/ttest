// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_EVENT_IMPL_HPP
#define VSOMEIP_EVENT_IMPL_HPP

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <atomic>

#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/steady_timer.hpp>

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/function_types.hpp>
#include <vsomeip/payload.hpp>

namespace vsomeip {

class endpoint;
class endpoint_definition;
class message;
class message_serializer;
class payload;
class routing_manager;

class event: public std::enable_shared_from_this<event> {
public:
    event(routing_manager *_routing, service_t _service, instance_t _instance,
          event_t _event, bool _is_shadow = false);

    service_t get_service() const;
    instance_t get_instance() const;
    event_t get_event() const;

    major_version_t get_version() const;
    void set_version(major_version_t _major);

    const std::vector<byte_t> get_message() const;
    const std::shared_ptr<payload> get_cached_payload() const;

    void set_payload(const std::shared_ptr<message_serializer> &_message_serializer,
                     std::shared_ptr<payload> &_payload, const byte_t domain_num_, bool _force, bool _flush);
    void set_payload(const std::shared_ptr<message_serializer> &_message_serializer,
                     std::shared_ptr<payload> &_payload, client_t _client, bool _force, bool _flush);
    void set_payload(const std::shared_ptr<message_serializer> &_message_serializer,
                     std::shared_ptr<payload> &_payload, const std::shared_ptr<endpoint_definition> &_target,
                     bool _force, bool _flush);

    void set_message(const byte_t *_data, length_t _size,
            const client_t _client, bool _force, bool _flush);

    void set_message(const byte_t *_data, length_t _size,
            const std::shared_ptr<endpoint_definition> _target,
            bool _force, bool _flush);

    bool set_message_dont_notify(const byte_t *_data, length_t _size);

    void set_message(const byte_t *_data, length_t _size,
            bool _force, bool _flush);
    void unset_message(bool _force = false);

    bool is_field() const;
    void set_field(bool _is_field);

    bool is_provided() const;
    void set_provided(bool _is_provided);

    bool is_set() const;
    bool is_cached_payload() const;

    // SIP_RPC_357
    void set_update_cycle(std::chrono::milliseconds &_cycle);
    void set_change_resets_cycle(bool _change_resets_cycle);

    // SIP_RPC_358
    void set_update_on_change(bool _is_on);

    // SIP_RPC_359 (epsilon change)
    void set_epsilon_change_function(const epsilon_change_func_t &_epsilon_change_func);

    const std::set<eventgroup_t> get_eventgroups() const;
    std::set<eventgroup_t> get_eventgroups(client_t _client) const;
    void add_eventgroup(eventgroup_t _eventgroup);
    void set_eventgroups(const std::set<eventgroup_t> &_eventgroups);

    void notify_one(const std::shared_ptr<endpoint_definition> &_target, bool _flush);
    void notify_one(client_t _client, bool _flush);

    bool add_subscriber(eventgroup_t _eventgroup, client_t _client, bool _force);
    void remove_subscriber(eventgroup_t _eventgroup, client_t _client);
    bool has_subscriber(eventgroup_t _eventgroup, client_t _client);
    std::set<client_t> get_subscribers();
    void clear_subscribers();

    void add_ref(client_t _client, bool _is_provided);
    void remove_ref(client_t _client, bool _is_provided);
    bool has_ref();

    bool is_shadow() const;
    void set_shadow(bool _shadow);

    bool is_cache_placeholder() const;
    void set_cache_placeholder(bool _is_cache_place_holder);

    bool has_ref(client_t _client, bool _is_provided);

    std::set<client_t> get_subscribers(eventgroup_t _eventgroup);

    bool is_subscribed(client_t _client);

    bool is_reliable() const;
    void set_reliable(bool _is_reliable);

    bool get_remote_notification_pending();
    void set_remote_notification_pending(bool _value);

private:
    void update_cbk(boost::system::error_code const &_error);
    void notify(bool _flush);
    void notify(client_t _client, const std::shared_ptr<endpoint_definition> &_target);

    void start_cycle();
    void stop_cycle();

    bool compare(const std::shared_ptr<payload> &_lhs, const std::shared_ptr<payload> &_rhs) const;

    bool set_payload_helper(const std::shared_ptr<payload> &_payload, bool _force);
    bool set_message_helper(const byte_t *_data, length_t _size, bool _force);
    void reset_message(const byte_t *_data, length_t _size);
    bool reset_payload(const std::shared_ptr<message_serializer> &_message_serializer,
                       const std::shared_ptr<payload> &_payload,
                       const byte_t domain_num_);

private:
    routing_manager *routing_;
    mutable std::mutex mutex_;

    std::vector<byte_t> message_;
    std::shared_ptr<payload> cached_payload_;

    const service_t service_;
    const instance_t instance_;
    const event_t event_;

    std::atomic<major_version_t> major_version_;

    boost::asio::steady_timer cycle_timer_;

    std::chrono::milliseconds cycle_;
    std::atomic<bool> change_resets_cycle_;

    std::atomic<bool> is_updating_on_change_;
    mutable std::mutex eventgroups_mutex_;

    std::map<eventgroup_t, std::set<client_t>> eventgroups_;

    std::atomic<bool> is_field_;
    std::atomic<bool> is_set_;
    std::atomic<bool> is_provided_;

    std::mutex refs_mutex_;
    std::map<client_t, std::map<bool, uint32_t>> refs_;

    std::atomic<bool> is_shadow_;
    std::atomic<bool> is_cache_placeholder_;

    epsilon_change_func_t epsilon_change_func_;

    std::atomic<bool> is_reliable_;

    std::atomic<bool> remote_notification_pending_;
};

}  // namespace vsomeip

#endif // VSOMEIP_EVENT_IMPL_HPP
