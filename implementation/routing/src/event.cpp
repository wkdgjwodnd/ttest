// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <algorithm>
#include <iomanip>

#include <vsomeip/constants.hpp>
#include <vsomeip/defines.hpp>
#include <vsomeip/message.hpp>
#include <vsomeip/payload.hpp>
#include <vsomeip/runtime.hpp>

#include "../include/event.hpp"
#include "../include/routing_manager.hpp"
#include "../../configuration/include/internal.hpp"
#include "../../logging/include/logger.hpp"
#include "../../message/include/payload_impl.hpp"
#include "../../security/include/message_serializer.hpp"

namespace vsomeip {

event::event(routing_manager *_routing, service_t _service, instance_t _instance, event_t _event, bool _is_shadow) :
        routing_(_routing),
        message_(),
        service_(_service),
        instance_(_instance),
        event_(_event),
        major_version_(0),
        cycle_timer_(_routing->get_io()),
        cycle_(std::chrono::milliseconds::zero()),
        change_resets_cycle_(false),
        is_updating_on_change_(true),
        is_field_(false),
        is_set_(false),
        is_provided_(false),
        is_shadow_(_is_shadow),
        is_cache_placeholder_(false),
        epsilon_change_func_(std::bind(&event::compare, this,
                                       std::placeholders::_1, std::placeholders::_2)),
        is_reliable_(false),
        remote_notification_pending_(false) {
}

service_t event::get_service() const {
    return service_;
}

instance_t event::get_instance() const {
    return instance_;
}

event_t event::get_event() const {
    return event_;
}

major_version_t event::get_version() const {
    return major_version_;
}

void event::set_version(major_version_t _major) {
    major_version_ = _major;
}

bool event::is_field() const {
    return (is_field_);
}

void event::set_field(bool _is_field) {
    is_field_ = _is_field;
}

bool event::is_provided() const {
    return (is_provided_);
}

void event::set_provided(bool _is_provided) {
    is_provided_ = _is_provided;
}

bool event::is_set() const {
    return is_set_;
}

bool event::is_cached_payload() const {
    std::lock_guard<std::mutex> its_lock(mutex_);
    return static_cast<bool>(cached_payload_);
}

const std::vector<byte_t> event::get_message() const {
    std::lock_guard<std::mutex> its_lock(mutex_);
    return std::vector<byte_t>(message_);
}

const std::shared_ptr<payload> event::get_cached_payload() const {
    std::lock_guard<std::mutex> its_lock(mutex_);
    return cached_payload_;
}

// =========================
/*
void event::set_payload(const std::shared_ptr<message_serializer> &_message_serializer,
                        std::shared_ptr<payload> &_payload, 
                        const byte_t domain_num_, bool _force, bool _flush) {

    VSOMEIP_WARNING << "<evnet::set_payload> set_payload 1";

    std::lock_guard<std::mutex> its_lock(mutex_);
    if (is_provided_) {
        VSOMEIP_WARNING << "<evnet::set_payload> is_provided_ is true";
        if (set_payload_helper(_payload, _force)) {
            VSOMEIP_WARNING << "<evnet::set_payload> set_payload_helper is true";
            if (reset_payload(_message_serializer, _payload, domain_num_)) {
                VSOMEIP_WARNING << "<evnet::set_payload> reset_payload is true";
                if (is_updating_on_change_) {
                    VSOMEIP_WARNING << "<evnet::set_payload> is_updating_on_change_ is true";
                    if (change_resets_cycle_) {
                        VSOMEIP_WARNING << "<evnet::set_payload> change_resets_cycle_ is true";
                        stop_cycle();
                    }
                    VSOMEIP_WARNING << "<evnet::set_payload> notify flush detect";
                    notify(_flush);

                    if (change_resets_cycle_)
                        start_cycle();
                }
            }
        }
    } else {
        VSOMEIP_INFO << "Can't set payload for event " << std::hex
                     << get_event() << " as it isn't provided";
    }
}
*/
void event::set_payload(const std::shared_ptr<message_serializer> &_message_serializer,
                        std::shared_ptr<payload> &_payload, 
                        const byte_t domain_num_, bool _force, bool _flush) {

    VSOMEIP_WARNING << "<evnet::set_payload> set_payload 1";

    std::lock_guard<std::mutex> its_lock(mutex_);
    if (is_provided_) {
        if (reset_payload(_message_serializer, _payload, domain_num_)) {
            // VSOMEIP_WARNING << "<evnet::set_payload> reset_payload is true";
            if (is_updating_on_change_) {
                // VSOMEIP_WARNING << "<evnet::set_payload> is_updating_on_change_ is true";
                if (change_resets_cycle_) {
                    // VSOMEIP_WARNING << "<evnet::set_payload> change_resets_cycle_ is true";
                    stop_cycle();
                }
                // VSOMEIP_WARNING << "<evnet::set_payload> notify flush detect";
                notify(_flush);

                if (change_resets_cycle_)
                    start_cycle();
            }
        }
        
    } else {
        VSOMEIP_INFO << "Can't set payload for event " << std::hex
                     << get_event() << " as it isn't provided";
    }
}
// =========================

void event::set_payload(const std::shared_ptr<message_serializer> &_message_serializer,
                        std::shared_ptr<payload> &_payload, client_t _client, bool _force, bool _flush) {

    VSOMEIP_WARNING << "<evnet::set_payload> set_payload 2";

    std::lock_guard<std::mutex> its_lock(mutex_);
    if (is_provided_) {
        if (set_payload_helper(_payload, _force)) {
            if (reset_payload(_message_serializer, _payload, 10)) {
                if (is_updating_on_change_) {
                    notify_one(_client, _flush);
                }
            }
        }
    } else {
        VSOMEIP_INFO << "Can't set payload for event " << std::hex
                     << get_event() << " as it isn't provided";
    }
}

void event::set_payload(const std::shared_ptr<message_serializer> &_message_serializer,
                        std::shared_ptr<payload> &_payload, const std::shared_ptr<endpoint_definition> &_target,
                        bool _force, bool _flush) {

    VSOMEIP_WARNING << "<evnet::set_payload> set_payload 3";

    std::lock_guard<std::mutex> its_lock(mutex_);
    if (is_provided_) {
        if (set_payload_helper(_payload, _force)) {
            if (reset_payload(_message_serializer, _payload, 10)) {
                if (is_updating_on_change_) {
                    notify_one(_target, _flush);
                }
            }
        }
    } else {
        VSOMEIP_INFO << "Can't set message for event " << std::hex
                     << get_event() << " as it isn't provided";
    }
}

bool event::set_message_dont_notify(const byte_t *_data, length_t _size) {
    std::lock_guard<std::mutex> its_lock(mutex_);
    if (is_cache_placeholder_) {
        reset_message(_data, _size);
    } else {
        if (set_message_helper(_data, _size, false)) {
            reset_message(_data, _size);
        } else {
            return false;
        }
    }
    return true;
}

void event::set_message(const byte_t *_data, length_t _size,
                        bool _force, bool _flush) {
    std::lock_guard<std::mutex> its_lock(mutex_);
    if (is_provided_) {
        if (set_message_helper(_data, _size, _force)) {
            reset_message(_data, _size);
            if (is_updating_on_change_) {
                if (change_resets_cycle_)
                    stop_cycle();

                notify(_flush);

                if (change_resets_cycle_)
                    start_cycle();
            }
        }
    } else {
        VSOMEIP_INFO << "Can't set message for event " << std::hex
                     << get_event() << " as it isn't provided";
    }
}

void event::set_message(const byte_t *_data, length_t _size, client_t _client,
                        bool _force, bool _flush) {
    std::lock_guard<std::mutex> its_lock(mutex_);
    if (is_provided_) {
        if (set_message_helper(_data, _size, _force)) {
            reset_message(_data, _size);
            if (is_updating_on_change_) {
                notify_one(_client, _flush);
            }
        }
    } else {
        VSOMEIP_INFO << "Can't set message for event " << std::hex
                     << get_event() << " as it isn't provided";
    }
}

void event::set_message(const byte_t *_data, length_t _size,
                        const std::shared_ptr<endpoint_definition> _target,
                        bool _force, bool _flush) {
    std::lock_guard<std::mutex> its_lock(mutex_);
    if (is_provided_) {
        if (set_message_helper(_data, _size, _force)) {
            reset_message(_data, _size);
            if (is_updating_on_change_) {
                notify_one(_target, _flush);
            }
        }
    } else {
        VSOMEIP_INFO << "Can't set message for event " << std::hex
                     << get_event() << " as it isn't provided";
    }
}

void event::unset_message(bool _force) {
    std::lock_guard<std::mutex> its_lock(mutex_);
    if (_force || is_provided_) {
        is_set_ = false;
        stop_cycle();
        message_.clear();
        cached_payload_.reset();
    }
}

void event::set_update_cycle(std::chrono::milliseconds &_cycle) {
    if (is_provided_) {
        std::lock_guard<std::mutex> its_lock(mutex_);
        stop_cycle();
        cycle_ = _cycle;
        start_cycle();
    }
}

void event::set_change_resets_cycle(bool _change_resets_cycle) {
    change_resets_cycle_ = _change_resets_cycle;
}

void event::set_update_on_change(bool _is_active) {
    if (is_provided_) {
        is_updating_on_change_ = _is_active;
    }
}

void event::set_epsilon_change_function(const epsilon_change_func_t &_epsilon_change_func) {
    if (_epsilon_change_func) {
        std::lock_guard<std::mutex> its_lock(mutex_);
        epsilon_change_func_ = _epsilon_change_func;
    }
}

const std::set<eventgroup_t> event::get_eventgroups() const {
    std::set<eventgroup_t> its_eventgroups;
    {
        std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
        for (const auto e : eventgroups_) {
            its_eventgroups.insert(e.first);
        }
    }
    return its_eventgroups;
}

std::set<eventgroup_t> event::get_eventgroups(client_t _client) const {
    std::set<eventgroup_t> its_eventgroups;

    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    for (auto e : eventgroups_) {
        if (e.second.find(_client) != e.second.end())
            its_eventgroups.insert(e.first);
    }
    return its_eventgroups;
}

void event::add_eventgroup(eventgroup_t _eventgroup) {
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    if (eventgroups_.find(_eventgroup) == eventgroups_.end())
        eventgroups_[_eventgroup] = std::set<client_t>();
}

void event::set_eventgroups(const std::set<eventgroup_t> &_eventgroups) {
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    for (auto e : _eventgroups)
        eventgroups_[e] = std::set<client_t>();
}

void event::update_cbk(boost::system::error_code const &_error) {
    if (!_error) {
        std::lock_guard<std::mutex> its_lock(mutex_);
        cycle_timer_.expires_from_now(cycle_);
        notify(true);
        std::function<void(boost::system::error_code const &)> its_handler =
                std::bind(&event::update_cbk, shared_from_this(),
                          std::placeholders::_1);
        cycle_timer_.async_wait(its_handler);
    }
}

void event::notify(bool _flush) {
    if (is_set_) {
        routing_->send(VSOMEIP_ROUTING_CLIENT, message_.data(), static_cast<length_t>(message_.size()),
                       get_instance(), _flush, is_reliable_);
    } else {
        VSOMEIP_INFO << "Notify event " << std::hex << get_event()
                << "failed. Event payload not set!";
    }
}

void event::notify_one(const std::shared_ptr<endpoint_definition> &_target, bool _flush) {
    if (is_set_) {
        routing_->send_to(_target, message_.data(), static_cast<length_t>(message_.size()),
                          get_instance(), _flush);
    } else {
        VSOMEIP_INFO << "Notify one event " << std::hex << get_event()
                     << "failed. Event payload not set!";
    }
}

void event::notify_one(client_t _client, bool _flush) {
    if (is_set_) {
        routing_->send(_client, message_.data(), static_cast<length_t>(message_.size()),
                       get_instance(), _flush, is_reliable_);
    } else {
        VSOMEIP_INFO << "Notify one event " << std::hex << get_event()
                     << " to client " << _client << " failed. Event payload not set!";
    }
}

bool event::set_payload_helper(const std::shared_ptr<payload> &_payload, bool _force) {
    return !is_field_ || !cached_payload_ || _force || epsilon_change_func_(cached_payload_, _payload);
}

bool event::set_message_helper(const byte_t *_data, length_t _size, bool _force) {
    return !is_field_ || _force || message_.size() != _size || !std::equal(message_.begin(), message_.end(), _data);
}

void event::reset_message(const byte_t *_data, length_t _size) {

    message_.assign(_data, _data + _size);
    cached_payload_.reset();

    if (!is_set_)
        start_cycle();

    is_set_ = true;
}

bool event::reset_payload(const std::shared_ptr<message_serializer> &_message_serializer,
                          const std::shared_ptr<payload> &_payload,
                          const byte_t domain_num_) {

    cached_payload_ = runtime::get()->create_payload(_payload->get_data(), _payload->get_length());
    if (!_message_serializer) {
        VSOMEIP_ERROR << "<evnet::reset_payload> !_message_serializer";
        return false;
    }

// ==================================
    VSOMEIP_WARNING << "<event::reset_payload> create notification";
// ==================================

    std::shared_ptr<message> its_notification = runtime::get()->create_notification(domain_num_);
    its_notification->set_service(service_);
    its_notification->set_instance(instance_);
    its_notification->set_method(event_);
    its_notification->set_interface_version(0);
    its_notification->set_payload(_payload);

    if (!_message_serializer->serialize_message(its_notification.get(), message_)) {
        VSOMEIP_INFO << "Serialization failed for event" << std::hex << get_event();
        cached_payload_.reset();
        if (is_set_) {
            stop_cycle();
            is_set_ = false;
        }
        return false;
    }

    if (!is_set_)
        start_cycle();

    is_set_ = true;
    return true;
}

void event::add_ref(client_t _client, bool _is_provided) {
    std::lock_guard<std::mutex> its_lock(refs_mutex_);
    auto its_client = refs_.find(_client);
    if (its_client == refs_.end()) {
        refs_[_client][_is_provided] = 1;
    } else {
        auto its_provided = its_client->second.find(_is_provided);
        if (its_provided == its_client->second.end()) {
            refs_[_client][_is_provided] = 1;
        } else {
            its_provided->second++;
        }
    }
}

void event::remove_ref(client_t _client, bool _is_provided) {
    std::lock_guard<std::mutex> its_lock(refs_mutex_);
    auto its_client = refs_.find(_client);
    if (its_client != refs_.end()) {
        auto its_provided = its_client->second.find(_is_provided);
        if (its_provided != its_client->second.end()) {
            its_provided->second--;
            if (0 == its_provided->second) {
                its_client->second.erase(_is_provided);
                if (0 == its_client->second.size()) {
                    refs_.erase(_client);
                }
            }
        }
    }
}

bool event::has_ref() {
    std::lock_guard<std::mutex> its_lock(refs_mutex_);
    return refs_.size() != 0;
}

bool event::add_subscriber(eventgroup_t _eventgroup, client_t _client, bool _force) {
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    bool ret = false;
    if (_force // remote events managed by rm_impl
            || is_provided_ // events provided by rm_proxies
            || is_shadow_ // local events managed by rm_impl
            || is_cache_placeholder_) {
        ret = eventgroups_[_eventgroup].insert(_client).second;
    } else {
        VSOMEIP_WARNING << __func__ << ": Didnt' insert client "
                << std::hex << std::setw(4) << std::setfill('0') << _client
                << "to eventgroup 0x"
                << std::hex << std::setw(4) << std::setfill('0') << _eventgroup;
    }
    return ret;
}

void event::remove_subscriber(eventgroup_t _eventgroup, client_t _client) {
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    auto find_eventgroup = eventgroups_.find(_eventgroup);
    if (find_eventgroup != eventgroups_.end())
        find_eventgroup->second.erase(_client);
}

bool event::has_subscriber(eventgroup_t _eventgroup, client_t _client) {
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    auto find_eventgroup = eventgroups_.find(_eventgroup);
    if (find_eventgroup != eventgroups_.end()) {
        if (_client == ANY_CLIENT) {
            return (find_eventgroup->second.size() > 0);
        } else {
            return (find_eventgroup->second.find(_client)
                    != find_eventgroup->second.end());
        }
    }
    return false;
}

std::set<client_t> event::get_subscribers() {
    std::set<client_t> its_subscribers;
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    for (const auto &e : eventgroups_)
        its_subscribers.insert(e.second.begin(), e.second.end());
    return its_subscribers;
}

void event::clear_subscribers() {
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    for (auto &e : eventgroups_)
        e.second.clear();
}

bool event::has_ref(client_t _client, bool _is_provided) {
    std::lock_guard<std::mutex> its_lock(refs_mutex_);
    auto its_client = refs_.find(_client);
    if (its_client != refs_.end()) {
        auto its_provided = its_client->second.find(_is_provided);
        if (its_provided != its_client->second.end()) {
            if (its_provided->second > 0) {
                return true;
            }
        }
    }
    return false;
}

bool event::is_shadow() const {
    return is_shadow_;
}

void event::set_shadow(bool _shadow) {
    is_shadow_ = _shadow;
}

bool event::is_cache_placeholder() const {
    return is_cache_placeholder_;
}

void event::set_cache_placeholder(bool _is_cache_place_holder) {
    is_cache_placeholder_ = _is_cache_place_holder;
}

void event::start_cycle() {
    if (std::chrono::milliseconds::zero() != cycle_) {
        cycle_timer_.expires_from_now(cycle_);
        std::function<void(boost::system::error_code const &)> its_handler =
                std::bind(&event::update_cbk, shared_from_this(),
                          std::placeholders::_1);
        cycle_timer_.async_wait(its_handler);
    }
}

void event::stop_cycle() {
    if (std::chrono::milliseconds::zero() != cycle_) {
        boost::system::error_code ec;
        cycle_timer_.cancel(ec);
    }
}

bool event::compare(const std::shared_ptr<payload> &_lhs,
                    const std::shared_ptr<payload> &_rhs) const {
    bool is_change = (_lhs->get_length() != _rhs->get_length());
    if (!is_change) {
        std::size_t its_pos = 0;
        const byte_t *its_old_data = _lhs->get_data();
        const byte_t *its_new_data = _rhs->get_data();
        while (!is_change && its_pos < _lhs->get_length()) {
            is_change = (*its_old_data++ != *its_new_data++);
            its_pos++;
        }
    }
    return is_change;
}

std::set<client_t> event::get_subscribers(eventgroup_t _eventgroup) {
    std::set<client_t> its_subscribers;
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    auto found_eventgroup = eventgroups_.find(_eventgroup);
    if (found_eventgroup != eventgroups_.end()) {
        its_subscribers = found_eventgroup->second;
    }
    return its_subscribers;
}

bool event::is_subscribed(client_t _client) {
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    for (const auto &egp : eventgroups_) {
        if (egp.second.find(_client) != egp.second.end()) {
            return true;
        }
    }
    return false;
}

bool event::is_reliable() const {
    return is_reliable_;
}

void event::set_reliable(bool _is_reliable) {
    is_reliable_ = _is_reliable;
}

bool event::get_remote_notification_pending() {
    return remote_notification_pending_;
}

void event::set_remote_notification_pending(bool _value) {
    remote_notification_pending_ = _value;
}

} // namespace vsomeip
