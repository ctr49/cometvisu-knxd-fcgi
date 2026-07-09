// Copyright (C) 2026 Christian Mayer and the CometVisu contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "knxd_client.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <queue>
#include <stdexcept>
#include <utility>

#include "../util/debug_log.h"
#include "../util/hex.h"
#include "knxd_protocol.h"

namespace cvknxd {

struct KnxdClient::Impl {
  int fd = -1;
  int cache_fd_ = -1;  // separate connection for cache operations
  bool group_socket_open = false;
  std::string socket_path_;           // stored for reconnect
  bool write_only_ = false;           // stored for reconnect
  std::vector<uint8_t> read_buffer_;  // buffered partial reads for non-blocking mode
  // Separate read buffer for the cache connection
  std::vector<uint8_t> cache_read_buffer_;
  uint64_t telegram_count_ = 0;  // total group telegrams received from knxd bus
  // Telegrams pre-parsed during cache_read(), already counted.
  // poll_group_telegram() drains this queue first without incrementing the counter.
  std::queue<std::pair<uint16_t, std::vector<uint8_t>>> pre_counted_telegrams_;

  ~Impl() {
    if (fd >= 0) {
      ::close(fd);
    }
    if (cache_fd_ >= 0) {
      ::close(cache_fd_);
    }
  }
};

KnxdClient::KnxdClient() : impl_(std::make_unique<Impl>()) {}

KnxdClient::~KnxdClient() = default;

KnxdClient::KnxdClient(KnxdClient&&) noexcept = default;
KnxdClient& KnxdClient::operator=(KnxdClient&&) noexcept = default;

bool KnxdClient::connect(std::string_view socket_path) {
  if (impl_->fd >= 0) {
    disconnect();
  }

  impl_->fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (impl_->fd < 0)
    return false;

  struct sockaddr_un addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  // Copy path safely
  if (socket_path.size() >= sizeof(addr.sun_path))
    return false;
  std::memcpy(addr.sun_path, socket_path.data(), socket_path.size());

  // Use non-blocking connect with timeout to avoid hanging indefinitely
  int flags = ::fcntl(impl_->fd, F_GETFL, 0);
  if (flags >= 0) {
    ::fcntl(impl_->fd, F_SETFL, flags | O_NONBLOCK);
  }

  int ret = ::connect(impl_->fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
  if (ret < 0 && errno != EINPROGRESS) {
    ::close(impl_->fd);
    impl_->fd = -1;
    return false;
  }

  if (ret < 0) {
    // Connection in progress — wait with timeout
    struct pollfd pfd;
    pfd.fd = impl_->fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    int poll_ret = ::poll(&pfd, 1, 5000);  // 5 second timeout
    if (poll_ret <= 0) {
      ::close(impl_->fd);
      impl_->fd = -1;
      return false;
    }
    // Check if connection succeeded
    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (::getsockopt(impl_->fd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0) {
      ::close(impl_->fd);
      impl_->fd = -1;
      return false;
    }
  }

  // Restore blocking mode (caller can set non-blocking via set_nonblocking())
  if (flags >= 0) {
    ::fcntl(impl_->fd, F_SETFL, flags & ~O_NONBLOCK);
  }

  // Store path for potential reconnect
  impl_->socket_path_ = socket_path;

  return true;
}

void KnxdClient::disconnect() {
  if (impl_->fd >= 0) {
    ::close(impl_->fd);
    impl_->fd = -1;
  }
  if (impl_->cache_fd_ >= 0) {
    ::close(impl_->cache_fd_);
    impl_->cache_fd_ = -1;
  }
  impl_->group_socket_open = false;
  impl_->read_buffer_.clear();
  impl_->cache_read_buffer_.clear();
  // Clear pre-counted telegram queue
  while (!impl_->pre_counted_telegrams_.empty())
    impl_->pre_counted_telegrams_.pop();
  // Note: socket_path_ and write_only_ are preserved for reconnect
}

bool KnxdClient::is_connected() const {
  return impl_->fd >= 0;
}

bool KnxdClient::reconnect() {
  if (impl_->socket_path_.empty())
    return false;  // never connected, nothing to reconnect to

  // Disconnect any stale state first
  if (impl_->fd >= 0) {
    ::close(impl_->fd);
    impl_->fd = -1;
  }
  if (impl_->cache_fd_ >= 0) {
    ::close(impl_->cache_fd_);
    impl_->cache_fd_ = -1;
  }
  impl_->group_socket_open = false;
  impl_->read_buffer_.clear();
  impl_->cache_read_buffer_.clear();
  while (!impl_->pre_counted_telegrams_.empty())
    impl_->pre_counted_telegrams_.pop();

  // Re-establish connection
  if (!connect(impl_->socket_path_))
    return false;

  // Re-open group socket with previous write_only setting
  if (!open_group_socket(impl_->write_only_)) {
    disconnect();
    return false;
  }

  // Restore non-blocking mode (the default for this application)
  set_nonblocking(true);

  return true;
}

namespace {

/// Write all bytes to socket. Handles EAGAIN in non-blocking mode by polling.
/// Returns true if all bytes were written.
bool write_all(int fd, const uint8_t* data, size_t len) {
  while (len > 0) {
    ssize_t written = ::write(fd, data, len);
    if (written < 0) {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Socket buffer full in non-blocking mode — wait for writability
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        int ret = ::poll(&pfd, 1, 5000);  // 5 second timeout
        if (ret <= 0)
          return false;  // timeout or error
        continue;        // retry write
      }
      return false;
    }
    data += written;
    len -= static_cast<size_t>(written);
  }
  return true;
}

/// Read a complete eibd message (length-prefixed) from the socket.
/// Uses an internal buffer to handle partial reads in non-blocking mode.
/// This is an iterative (non-recursive) implementation to avoid stack overflow
/// on busy KNX buses with many partial reads.
/// @param fd Socket file descriptor.
/// @param buffer Accumulated read buffer (consumed as messages are parsed).
///              Enforced maximum size of kMaxReadBufferSize to prevent memory leaks.
/// @return Complete message bytes (including 2-byte length header), or std::nullopt.
std::optional<std::vector<uint8_t>> read_message(int fd, std::vector<uint8_t>& buffer) {
  while (true) {
    // Try to extract a complete message from the buffer (pure function, no I/O)
    auto msg = try_extract_message(buffer);
    if (msg.has_value())
      return msg;

    // Need more data — read from socket
    uint8_t tmp[4096];
    ssize_t n = ::read(fd, tmp, sizeof(tmp));
    if (n > 0) {
      // Enforce maximum buffer size to prevent unbounded memory growth.
      // If the buffer would exceed the limit, discard the oldest data first.
      size_t new_size = buffer.size() + static_cast<size_t>(n);
      if (new_size > kMaxReadBufferSize) {
        size_t excess = new_size - kMaxReadBufferSize;
        // Discard from the front — this may lose a partial message,
        // but prevents OOM on a constrained system.
        if (excess >= buffer.size()) {
          buffer.clear();
        } else {
          buffer.erase(buffer.begin(), buffer.begin() + static_cast<ptrdiff_t>(excess));
        }
      }
      buffer.insert(buffer.end(), tmp, tmp + n);
      // Loop back to try parsing again with new data
      continue;
    }
    if (n == 0) {
      return std::nullopt;  // EOF — connection closed
    }
    // n < 0
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return std::nullopt;  // No data available in non-blocking mode
    }
    if (errno == EINTR) {
      continue;  // Retry on signal
    }
    return std::nullopt;  // Real error
  }
}

}  // namespace

bool KnxdClient::open_group_socket(bool write_only) {
  if (!is_connected())
    return false;

  impl_->write_only_ = write_only;

  auto msg = build_open_groupcon(write_only);

  DebugLog::knxd_send("open_group_socket", "-",
                      write_only ? "write_only=true" : "write_only=false");

  if (!write_all(impl_->fd, msg.data(), msg.size()))
    return false;

  // Read response
  auto resp = read_message(impl_->fd, impl_->read_buffer_);
  if (!resp)
    return false;

  uint16_t resp_type;
  std::vector<uint8_t> resp_data;
  if (!parse_eibd_message(*resp, resp_type, resp_data))
    return false;

  // Success: response is OPEN_GROUPCON with no error
  impl_->group_socket_open = (resp_type == EibMessageType::OPEN_GROUPCON);
  return impl_->group_socket_open;
}

bool KnxdClient::send_group_packet(uint16_t group_addr, const std::vector<uint8_t>& apdu) {
  if (!is_connected() || !impl_->group_socket_open) {
    // Attempt transparent reconnect once
    if (!reconnect())
      return false;
  }

  auto addr_str = KnxGroupAddress::from_eibaddr(group_addr).to_string();

  DebugLog::knxd_send("group_packet", addr_str, "apdu=" + hex_encode(apdu.data(), apdu.size()));

  auto msg = build_group_packet(group_addr, apdu);
  return write_all(impl_->fd, msg.data(), msg.size());
}

int* KnxdClient::ensure_cache_connection() {
  if (impl_->cache_fd_ >= 0)
    return &impl_->cache_fd_;

  std::cerr << "[DEBUG] cache_connect: opening to " << impl_->socket_path_ << std::endl;

  impl_->cache_fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (impl_->cache_fd_ < 0) {
    std::cerr << "[DEBUG] cache_connect: socket() failed: " << strerror(errno) << std::endl;
    return nullptr;
  }

  struct sockaddr_un addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (impl_->socket_path_.size() >= sizeof(addr.sun_path)) {
    std::cerr << "[DEBUG] cache_connect: path too long" << std::endl;
    ::close(impl_->cache_fd_);
    impl_->cache_fd_ = -1;
    return nullptr;
  }
  std::memcpy(addr.sun_path, impl_->socket_path_.data(), impl_->socket_path_.size());

  if (::connect(impl_->cache_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
    std::cerr << "[DEBUG] cache_connect: connect() failed: " << strerror(errno) << std::endl;
    ::close(impl_->cache_fd_);
    impl_->cache_fd_ = -1;
    return nullptr;
  }

  // Set non-blocking
  int flags = ::fcntl(impl_->cache_fd_, F_GETFL, 0);
  if (flags >= 0) {
    ::fcntl(impl_->cache_fd_, F_SETFL, flags | O_NONBLOCK);
  }

  std::cerr << "[DEBUG] cache_connect: connected fd=" << impl_->cache_fd_ << std::endl;
  return &impl_->cache_fd_;
}

std::optional<std::vector<uint8_t>> KnxdClient::cache_read(uint16_t group_addr, bool nowait) {
  // Ensure we have a cache connection (separate from the group socket).
  // Cache operations don't work on connections that have OPEN_GROUPCON active.
  auto* cache_fd = ensure_cache_connection();
  if (cache_fd == nullptr)
    return std::nullopt;

  auto addr_str = KnxGroupAddress::from_eibaddr(group_addr).to_string();

  DebugLog::knxd_send("cache_read", addr_str, nowait ? "nowait=true" : "nowait=false");

  uint16_t msg_type = nowait ? EibMessageType::CACHE_READ_NOWAIT : EibMessageType::CACHE_READ;
  auto msg = nowait ? build_cache_read_nowait(group_addr) : build_cache_read(group_addr);
  if (!write_all(*cache_fd, msg.data(), msg.size()))
    return std::nullopt;

  // Read response from the cache connection.
  // The cache connection is a plain connection (no group socket), so we won't
  // receive APDU_PACKET telegrams here — only the cache response.
  // 5 second deadline for the cache_read response (generous for local Unix socket)
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);

  while (true) {
    // Try to extract a complete message from the cache buffer first (no I/O)
    auto raw_msg = try_extract_message(impl_->cache_read_buffer_);
    if (raw_msg.has_value()) {
      uint16_t resp_type;
      std::vector<uint8_t> resp_data;
      if (!parse_eibd_message(*raw_msg, resp_type, resp_data)) {
        continue;  // malformed message, try next
      }

      if (resp_type == msg_type && resp_data.size() >= 4) {
        // This is our cache response.
        // Response format: src(2) + dst(2) + [apdu_data...]
        if (resp_data.size() == 4) {
          // Cache miss: only src+dst, no APDU data
          DebugLog::knxd_recv("cache_read_miss", addr_str, "(empty)");
          return std::nullopt;
        }
        // Cache hit: extract APDU data after src(2)+dst(2)
        auto apdu = std::vector<uint8_t>(resp_data.begin() + 4, resp_data.end());

        // Strip the APDU header and filter out Read APDUs.
        ApduType apdu_type;
        std::vector<uint8_t> value_data;
        if (!parse_apdu(apdu, apdu_type, value_data))
          return std::nullopt;
        if (apdu_type == ApduType::Read)
          return std::nullopt;

        DebugLog::knxd_recv("cache_read", addr_str,
                            hex_encode(value_data.data(), value_data.size()));
        return value_data;
      }

      // Unknown message on cache connection — discard
      continue;
    }

    // No complete message in buffer — need more data from cache socket.
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                         deadline - std::chrono::steady_clock::now())
                         .count();
    if (remaining <= 0)
      return std::nullopt;

    struct pollfd pfd = {};
    pfd.fd = *cache_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int poll_ret = ::poll(&pfd, 1, static_cast<int>(remaining));
    if (poll_ret < 0) {
      if (errno == EINTR)
        continue;
      return std::nullopt;
    }
    if (poll_ret == 0)
      return std::nullopt;

    if ((pfd.revents & (POLLHUP | POLLERR)) != 0)
      return std::nullopt;

    // Read data from cache socket
    uint8_t tmp[4096];
    ssize_t n = ::read(*cache_fd, tmp, sizeof(tmp));
    if (n > 0) {
      size_t new_size = impl_->cache_read_buffer_.size() + static_cast<size_t>(n);
      if (new_size > kMaxReadBufferSize) {
        size_t excess = new_size - kMaxReadBufferSize;
        if (excess >= impl_->cache_read_buffer_.size()) {
          impl_->cache_read_buffer_.clear();
        } else {
          impl_->cache_read_buffer_.erase(
              impl_->cache_read_buffer_.begin(),
              impl_->cache_read_buffer_.begin() + static_cast<ptrdiff_t>(excess));
        }
      }
      impl_->cache_read_buffer_.insert(impl_->cache_read_buffer_.end(), tmp, tmp + n);
      continue;
    }
    if (n == 0)
      return std::nullopt;
    if (errno == EINTR)
      continue;
    return std::nullopt;  // error
  }
}

int KnxdClient::get_fd() const {
  return impl_->fd;
}

uint64_t KnxdClient::get_telegram_count() const {
  return impl_->telegram_count_;
}

void KnxdClient::set_nonblocking(bool enable) {
  if (impl_->fd < 0)
    return;
  int flags = ::fcntl(impl_->fd, F_GETFL, 0);
  if (flags < 0)
    return;
  if (enable) {
    ::fcntl(impl_->fd, F_SETFL, flags | O_NONBLOCK);
  } else {
    ::fcntl(impl_->fd, F_SETFL, flags & ~O_NONBLOCK);
  }
}

bool KnxdClient::poll_group_telegram(uint16_t& out_group_addr, std::vector<uint8_t>& out_apdu) {
  if (!is_connected()) {
    // Attempt transparent reconnect once
    if (!reconnect())
      return false;
  }

  // Check pre-counted queue first (telegrams already parsed and counted
  // during cache_read). Do NOT increment telegram_count_ for these.
  if (!impl_->pre_counted_telegrams_.empty()) {
    auto& front = impl_->pre_counted_telegrams_.front();
    out_group_addr = front.first;
    out_apdu = std::move(front.second);
    impl_->pre_counted_telegrams_.pop();

    DebugLog::knxd_recv("apdu_packet", KnxGroupAddress::from_eibaddr(out_group_addr).to_string(),
                        hex_encode(out_apdu.data(), out_apdu.size()));

    return true;
  }

  // Try non-blocking read of message (uses internal buffer)
  auto msg = read_message(impl_->fd, impl_->read_buffer_);
  if (!msg)
    return false;

  uint16_t msg_type;
  std::vector<uint8_t> msg_data;
  if (!parse_eibd_message(*msg, msg_type, msg_data))
    return false;

  if (msg_type == EibMessageType::APDU_PACKET && msg_data.size() >= 6) {
    // Format: src_pa(2) + dst_ga(2) + apdu...
    // The dst_ga is the group address the telegram was sent to.
    out_group_addr = static_cast<uint16_t>((msg_data[2] << 8) | msg_data[3]);
    out_apdu.assign(msg_data.begin() + 4, msg_data.end());

    DebugLog::knxd_recv("apdu_packet", KnxGroupAddress::from_eibaddr(out_group_addr).to_string(),
                        hex_encode(out_apdu.data(), out_apdu.size()));

    impl_->telegram_count_++;
    return true;
  }

  if (msg_type == EibMessageType::GROUP_PACKET && msg_data.size() >= 6) {
    // Format from injected telegrams (e.g. knxtool groupswrite local:):
    // src_pa(2) + dst_ga(2) + apdu...
    // Note: this differs from GROUP_PACKET we send, which has format
    // [dst_ga(2)][apdu(N)]. knxd forwards injected telegrams with the
    // source PA prepended.
    out_group_addr = static_cast<uint16_t>((msg_data[2] << 8) | msg_data[3]);
    out_apdu.assign(msg_data.begin() + 4, msg_data.end());

    DebugLog::knxd_recv("group_packet_injected",
                        KnxGroupAddress::from_eibaddr(out_group_addr).to_string(),
                        hex_encode(out_apdu.data(), out_apdu.size()));

    impl_->telegram_count_++;
    return true;
  }

  return false;
}

std::optional<LastUpdatesResult> KnxdClient::cache_last_updates_2(uint32_t start, int timeout_sec) {
  // Ensure we have a cache connection (separate from the group socket).
  auto* cache_fd = ensure_cache_connection();
  if (cache_fd == nullptr)
    return std::nullopt;

  auto msg = build_cache_last_updates_2(start, timeout_sec);
  DebugLog::knxd_send("cache_last_updates_2", "",
                      "start=" + std::to_string(start) + " timeout=" + std::to_string(timeout_sec));

  if (!write_all(*cache_fd, msg.data(), msg.size()))
    return std::nullopt;

  // Read response from the cache connection.
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec + 5);

  while (true) {
    auto raw_msg = try_extract_message(impl_->cache_read_buffer_);
    if (raw_msg.has_value()) {
      uint16_t resp_type;
      std::vector<uint8_t> resp_data;
      if (!parse_eibd_message(*raw_msg, resp_type, resp_data)) {
        continue;
      }

      if (resp_type == EibMessageType::CACHE_LAST_UPDATES_2) {
        auto result = parse_cache_last_updates_2_response(resp_data);
        if (result) {
          DebugLog::knxd_recv("cache_last_updates_2", "",
                              "end=" + std::to_string(result->new_position) +
                                  " changed=" + std::to_string(result->changed_addresses.size()));
        }
        return result;
      }

      continue;  // Unknown message on cache connection — skip
    }

    // Need more data
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                         deadline - std::chrono::steady_clock::now())
                         .count();
    if (remaining <= 0)
      return std::nullopt;

    struct pollfd pfd = {};
    pfd.fd = *cache_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int poll_ret = ::poll(&pfd, 1, static_cast<int>(remaining));
    if (poll_ret < 0) {
      if (errno == EINTR)
        continue;
      return std::nullopt;
    }
    if (poll_ret == 0)
      return std::nullopt;

    if ((pfd.revents & (POLLHUP | POLLERR)) != 0)
      return std::nullopt;

    uint8_t tmp[4096];
    ssize_t n = ::read(*cache_fd, tmp, sizeof(tmp));
    if (n > 0) {
      size_t new_size = impl_->cache_read_buffer_.size() + static_cast<size_t>(n);
      if (new_size > kMaxReadBufferSize) {
        size_t excess = new_size - kMaxReadBufferSize;
        if (excess >= impl_->cache_read_buffer_.size()) {
          impl_->cache_read_buffer_.clear();
        } else {
          impl_->cache_read_buffer_.erase(
              impl_->cache_read_buffer_.begin(),
              impl_->cache_read_buffer_.begin() + static_cast<ptrdiff_t>(excess));
        }
      }
      impl_->cache_read_buffer_.insert(impl_->cache_read_buffer_.end(), tmp, tmp + n);
      continue;
    }
    if (n == 0)
      return std::nullopt;
    if (errno == EINTR)
      continue;
    return std::nullopt;
  }
}

}  // namespace cvknxd
