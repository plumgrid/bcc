/*
 * Copyright (c) 2016 Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fcntl.h>
#include <linux/elf.h>
#include <linux/perf_event.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>

#include "BPFTable.h"

#include "bcc_exception.h"
#include "bcc_syms.h"
#include "common.h"
#include "file_desc.h"
#include "libbpf.h"
#include "perf_reader.h"

namespace ebpf {

BPFTable::BPFTable(const TableDesc& desc) : BPFTableBase<void, void>(desc) {}

StatusTuple BPFTable::get_value(const std::string& key_str,
                                std::string& value_str) {
  char key[desc.key_size];
  char value[desc.leaf_size];

  StatusTuple r(0);

  r = string_to_key(key_str, key);
  if (!r.ok())
    return r;

  if (!lookup(key, value))
    return StatusTuple(-1, "error getting value");

  return leaf_to_string(value, value_str);
}

StatusTuple BPFTable::get_value(const std::string& key_str,
                                std::vector<std::string>& value_str) {
  size_t ncpus = get_possible_cpus().size();
  char key[desc.key_size];
  char value[desc.leaf_size * ncpus];

  StatusTuple r(0);

  r = string_to_key(key_str, key);
  if (!r.ok())
    return r;

  if (!lookup(key, value))
    return StatusTuple(-1, "error getting value");

  value_str.resize(ncpus);

  for (size_t i = 0; i < ncpus; i++) {
    r = leaf_to_string(value + i * desc.leaf_size, value_str.at(i));
    if (!r.ok())
      return r;
  }
  return StatusTuple::OK();
}

StatusTuple BPFTable::update_value(const std::string& key_str,
                                   const std::string& value_str) {
  char key[desc.key_size];
  char value[desc.leaf_size];

  StatusTuple r(0);

  r = string_to_key(key_str, key);
  if (!r.ok())
    return r;

  r = string_to_leaf(value_str, value);
  if (!r.ok())
    return r;

  if (!update(key, value))
    return StatusTuple(-1, "error updating element");

  return StatusTuple::OK();
}

StatusTuple BPFTable::update_value(const std::string& key_str,
                                   const std::vector<std::string>& value_str) {
  size_t ncpus = get_possible_cpus().size();
  char key[desc.key_size];
  char value[desc.leaf_size * ncpus];

  StatusTuple r(0);

  r = string_to_key(key_str, key);
  if (!r.ok())
    return r;

  if (value_str.size() != ncpus)
    return StatusTuple(-1, "bad value size");

  for (size_t i = 0; i < ncpus; i++) {
    r = string_to_leaf(value_str.at(i), value + i * desc.leaf_size);
    if (!r.ok())
      return r;
  }

  if (!update(key, value))
    return StatusTuple(-1, "error updating element");

  return StatusTuple::OK();
}

StatusTuple BPFTable::remove_value(const std::string& key_str) {
  char key[desc.key_size];

  StatusTuple r(0);

  r = string_to_key(key_str, key);
  if (!r.ok())
    return r;

  if (!remove(key))
    return StatusTuple(-1, "error removing element");

  return StatusTuple::OK();
}

StatusTuple BPFTable::clear_table_non_atomic() {
  if (desc.type == BPF_MAP_TYPE_HASH ||
      desc.type == BPF_MAP_TYPE_LRU_HASH ||
      desc.type == BPF_MAP_TYPE_PERCPU_HASH ||
      desc.type == BPF_MAP_TYPE_HASH_OF_MAPS) {
    // For hash maps, use the first() interface (which uses get_next_key) to
    // iterate through the map and clear elements
    auto key = std::unique_ptr<void, decltype(::free)*>(::malloc(desc.key_size),
                                                        ::free);

    while (this->first(key.get()))
      if (!this->remove(key.get())) {
        return StatusTuple(-1,
                           "Failed to delete element when clearing table %s",
                           desc.name.c_str());
      }
  } else if (desc.type == BPF_MAP_TYPE_ARRAY ||
             desc.type == BPF_MAP_TYPE_PERCPU_ARRAY) {
    return StatusTuple(-1, "Array map %s do not support clearing elements",
                       desc.name.c_str());
  } else if (desc.type == BPF_MAP_TYPE_PROG_ARRAY ||
             desc.type == BPF_MAP_TYPE_PERF_EVENT_ARRAY ||
             desc.type == BPF_MAP_TYPE_STACK_TRACE ||
             desc.type == BPF_MAP_TYPE_ARRAY_OF_MAPS) {
    // For Stack-trace and FD arrays, just iterate over all indices
    for (size_t i = 0; i < desc.max_entries; i++) {
      this->remove(&i);
    }
  } else {
    return StatusTuple(-1, "Clearing for map type of %s not supported yet",
                       desc.name.c_str());
  }

  return StatusTuple::OK();
}

StatusTuple BPFTable::get_table_offline(
  std::vector<std::pair<std::string, std::string>> &res) {
  StatusTuple r(0);

  res.clear();

  void* cursor = nullptr;

  std::string key_str;
  std::string value_str;

  bool multi_batch;
  size_t count;
  if (desc.type == BPF_MAP_TYPE_ARRAY ||
      desc.type == BPF_MAP_TYPE_PROG_ARRAY ||
      desc.type == BPF_MAP_TYPE_PERF_EVENT_ARRAY ||
      desc.type == BPF_MAP_TYPE_PERCPU_ARRAY ||
      desc.type == BPF_MAP_TYPE_CGROUP_ARRAY ||
      desc.type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
      desc.type == BPF_MAP_TYPE_DEVMAP ||
      desc.type == BPF_MAP_TYPE_CPUMAP ||
      desc.type == BPF_MAP_TYPE_REUSEPORT_SOCKARRAY) {
    // For arrays, just iterate over all indices
    count = desc.max_entries;
    multi_batch = false;
  } else {
    count = std::min(desc.max_entries, MAX_BATCH_SIZE);
    multi_batch = true;
  }
  std::unique_ptr<char[]> keys = std::make_unique<char[]>(count * desc.key_size);
  std::unique_ptr<char[]> values = std::make_unique<char[]>(count * desc.leaf_size);
  do {
    int64_t n_read = this->lookup_batch(keys.get(), values.get(), &cursor, count);
    if (n_read < 0) {
      r = StatusTuple(-1, "lookup_batch return error: %s", std::strerror(errno));
      return r;
    }

    char* key = keys.get(), * value = values.get();
    for (size_t i = 0; i < n_read; i++) {
      r = key_to_string(key, key_str);
      if (!r.ok())
        return r;

      r = leaf_to_string(value, value_str);
      if (!r.ok())
        return r;
      res.emplace_back(key_str, value_str);
      key += desc.key_size;
      value += desc.leaf_size;
    }

    if (n_read < count)
      break;
  } while (multi_batch);

  return StatusTuple::OK();
}

size_t BPFTable::get_possible_cpu_count() { return get_possible_cpus().size(); }

BPFStackTable::BPFStackTable(const TableDesc& desc, bool use_debug_file,
                             bool check_debug_file_crc)
    : BPFTableBase<int, stacktrace_t>(desc) {
  if (desc.type != BPF_MAP_TYPE_STACK_TRACE)
    throw std::invalid_argument("Table '" + desc.name +
                                "' is not a stack table");

  uint32_t use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC);
  symbol_option_ = {.use_debug_file = use_debug_file,
                    .check_debug_file_crc = check_debug_file_crc,
                    .lazy_symbolize = 1,
                    .use_symbol_type = use_symbol_type};
}

BPFStackTable::BPFStackTable(BPFStackTable&& that)
    : BPFTableBase<int, stacktrace_t>(that.desc),
      symbol_option_(std::move(that.symbol_option_)),
      pid_sym_(std::move(that.pid_sym_)) {
  that.pid_sym_.clear();
}

BPFStackTable::~BPFStackTable() {
  for (auto it : pid_sym_)
    bcc_free_symcache(it.second, it.first);
}

void BPFStackTable::free_symcache(int pid) {
  auto iter = pid_sym_.find(pid);
  if (iter != pid_sym_.end()) {
    bcc_free_symcache(iter->second, iter->first);
    pid_sym_.erase(iter);
  }
}

void BPFStackTable::clear_table_non_atomic() {
  for (int i = 0; size_t(i) < capacity(); i++) {
    remove(&i);
  }
}

std::vector<uintptr_t> BPFStackTable::get_stack_addr(int stack_id) {
  std::vector<uintptr_t> res;
  stacktrace_t stack;
  if (stack_id < 0)
    return res;
  if (!lookup(&stack_id, &stack))
    return res;
  for (int i = 0; (i < BPF_MAX_STACK_DEPTH) && (stack.ip[i] != 0); i++)
    res.push_back(stack.ip[i]);
  return res;
}

std::vector<std::string> BPFStackTable::get_stack_symbol(int stack_id,
                                                         int pid) {
  auto addresses = get_stack_addr(stack_id);
  std::vector<std::string> res;
  if (addresses.empty())
    return res;
  res.reserve(addresses.size());

  if (pid < 0)
    pid = -1;
  if (pid_sym_.find(pid) == pid_sym_.end())
    pid_sym_[pid] = bcc_symcache_new(pid, &symbol_option_);
  void* cache = pid_sym_[pid];

  bcc_symbol symbol;
  for (auto addr : addresses)
    if (bcc_symcache_resolve(cache, addr, &symbol) != 0)
      res.emplace_back("[UNKNOWN]");
    else {
      res.push_back(symbol.demangle_name);
      bcc_symbol_free_demangle_name(&symbol);
    }

  return res;
}

BPFStackBuildIdTable::BPFStackBuildIdTable(const TableDesc& desc, bool use_debug_file,
                                           bool check_debug_file_crc,
                                           void *bsymcache)
    : BPFTableBase<int, stacktrace_buildid_t>(desc),
      bsymcache_(bsymcache) {
  if (desc.type != BPF_MAP_TYPE_STACK_TRACE)
    throw std::invalid_argument("Table '" + desc.name +
                                "' is not a stack table");

  symbol_option_ = {.use_debug_file = use_debug_file,
                    .check_debug_file_crc = check_debug_file_crc,
                    .lazy_symbolize = 1,
                    .use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC)};
}

void BPFStackBuildIdTable::clear_table_non_atomic() {
  for (int i = 0; size_t(i) < capacity(); i++) {
    remove(&i);
  }
}

std::vector<bpf_stack_build_id> BPFStackBuildIdTable::get_stack_addr(int stack_id) {
  std::vector<bpf_stack_build_id> res;
  struct stacktrace_buildid_t stack;
  if (stack_id < 0)
    return res;
  if (!lookup(&stack_id, &stack))
    return res;
  for (int i = 0; (i < BPF_MAX_STACK_DEPTH) && \
       (stack.trace[i].status == BPF_STACK_BUILD_ID_VALID);
       i++) {
        /* End of stack marker is BCC_STACK_BUILD_ID_EMPTY or
         * BCC_STACK_BUILD_IP(fallback) mechanism.
         * We do not support fallback mechanism
         */
    res.push_back(stack.trace[i]);
  }
  return res;
}

std::vector<std::string> BPFStackBuildIdTable::get_stack_symbol(int stack_id)
{
  auto addresses = get_stack_addr(stack_id);
  std::vector<std::string> res;
  if (addresses.empty())
    return res;
  res.reserve(addresses.size());

  bcc_symbol symbol;
  struct bpf_stack_build_id trace;
  for (auto addr : addresses) {
    memcpy(trace.build_id, addr.build_id, sizeof(trace.build_id));
    trace.status = addr.status;
    trace.offset = addr.offset;
    if (bcc_buildsymcache_resolve(bsymcache_,&trace,&symbol) != 0) {
      res.emplace_back("[UNKNOWN]");
    } else {
      res.push_back(symbol.name);
      bcc_symbol_free_demangle_name(&symbol);
    }
  }
  return res;
}

BPFPerfBuffer::BPFPerfBuffer(const TableDesc& desc)
    : BPFTableBase<int, int>(desc), epfd_(-1) {
  if (desc.type != BPF_MAP_TYPE_PERF_EVENT_ARRAY)
    throw std::invalid_argument("Table '" + desc.name +
                                "' is not a perf buffer");
}

StatusTuple BPFPerfBuffer::open_on_cpu(perf_reader_raw_cb cb, perf_reader_lost_cb lost_cb,
                                       void* cb_cookie, int page_cnt,
                                       struct bcc_perf_buffer_opts& opts) {
  if (cpu_readers_.find(opts.cpu) != cpu_readers_.end())
    return StatusTuple(-1, "Perf buffer already open on CPU %d", opts.cpu);

  auto reader = static_cast<perf_reader*>(
      bpf_open_perf_buffer_opts(cb, lost_cb, cb_cookie, page_cnt, &opts));
  if (reader == nullptr)
    return StatusTuple(-1, "Unable to construct perf reader");

  int reader_fd = perf_reader_fd(reader);
  if (!update(&opts.cpu, &reader_fd)) {
    perf_reader_free(static_cast<void*>(reader));
    return StatusTuple(-1, "Unable to open perf buffer on CPU %d: %s", opts.cpu,
                       std::strerror(errno));
  }

  struct epoll_event event = {};
  event.events = EPOLLIN;
  event.data.ptr = static_cast<void*>(reader);
  if (epoll_ctl(epfd_, EPOLL_CTL_ADD, reader_fd, &event) != 0) {
    perf_reader_free(static_cast<void*>(reader));
    return StatusTuple(-1, "Unable to add perf_reader FD to epoll: %s",
                       std::strerror(errno));
  }

  cpu_readers_[opts.cpu] = reader;
  return StatusTuple::OK();
}

StatusTuple BPFPerfBuffer::open_all_cpu(perf_reader_raw_cb cb,
                                        perf_reader_lost_cb lost_cb,
                                        void* cb_cookie, int page_cnt) {
  return open_all_cpu(cb, lost_cb, cb_cookie, page_cnt, 1);
}

StatusTuple BPFPerfBuffer::open_all_cpu(perf_reader_raw_cb cb,
                                        perf_reader_lost_cb lost_cb,
                                        void* cb_cookie, int page_cnt,
                                        int wakeup_events)
{
  if (cpu_readers_.size() != 0 || epfd_ != -1)
    return StatusTuple(-1, "Previously opened perf buffer not cleaned");

  std::vector<int> cpus = get_online_cpus();
  ep_events_.reset(new epoll_event[cpus.size()]);
  epfd_ = epoll_create1(EPOLL_CLOEXEC);

  for (int i : cpus) {
    struct bcc_perf_buffer_opts opts = {
      .pid = -1,
      .cpu = i,
      .wakeup_events = wakeup_events,
    };
    auto res = open_on_cpu(cb, lost_cb, cb_cookie, page_cnt, opts);
    if (!res.ok()) {
      TRY2(close_all_cpu());
      return res;
    }
  }
  return StatusTuple::OK();
}

StatusTuple BPFPerfBuffer::close_on_cpu(int cpu) {
  auto it = cpu_readers_.find(cpu);
  if (it == cpu_readers_.end())
    return StatusTuple::OK();
  perf_reader_free(static_cast<void*>(it->second));
  if (!remove(const_cast<int*>(&(it->first))))
    return StatusTuple(-1, "Unable to close perf buffer on CPU %d", it->first);
  cpu_readers_.erase(it);
  return StatusTuple::OK();
}

StatusTuple BPFPerfBuffer::close_all_cpu() {
  std::string errors;
  bool has_error = false;

  if (epfd_ >= 0) {
    int close_res = close(epfd_);
    epfd_ = -1;
    ep_events_.reset();
    if (close_res != 0) {
      has_error = true;
      errors += std::string(std::strerror(errno)) + "\n";
    }
  }

  std::vector<int> opened_cpus;
  for (auto it : cpu_readers_)
    opened_cpus.push_back(it.first);
  for (int i : opened_cpus) {
    auto res = close_on_cpu(i);
    if (!res.ok()) {
      errors += "Failed to close CPU" + std::to_string(i) + " perf buffer: ";
      errors += res.msg() + "\n";
      has_error = true;
    }
  }

  if (has_error)
    return StatusTuple(-1, errors);
  return StatusTuple::OK();
}

int BPFPerfBuffer::poll(int timeout_ms) {
  if (epfd_ < 0)
    return -1;
  int cnt =
      epoll_wait(epfd_, ep_events_.get(), cpu_readers_.size(), timeout_ms);
  for (int i = 0; i < cnt; i++)
    perf_reader_event_read(static_cast<perf_reader*>(ep_events_[i].data.ptr));
  return cnt;
}

int BPFPerfBuffer::consume() {
  if (epfd_ < 0)
    return -1;
  for (auto it : cpu_readers_)
    perf_reader_event_read(it.second);
  return 0;
}

BPFPerfBuffer::~BPFPerfBuffer() {
  auto res = close_all_cpu();
  if (!res.ok())
    std::cerr << "Failed to close all perf buffer on destruction: " << res.msg()
              << std::endl;
}

BPFPerfEventArray::BPFPerfEventArray(const TableDesc& desc)
    : BPFTableBase<int, int>(desc) {
  if (desc.type != BPF_MAP_TYPE_PERF_EVENT_ARRAY)
    throw std::invalid_argument("Table '" + desc.name +
                                "' is not a perf event array");
}

StatusTuple BPFPerfEventArray::open_all_cpu(uint32_t type, uint64_t config,
                                            int pid) {
  if (cpu_fds_.size() != 0)
    return StatusTuple(-1, "Previously opened perf event not cleaned");

  std::vector<int> cpus = get_online_cpus();

  for (int i : cpus) {
    auto res = open_on_cpu(i, type, config, pid);
    if (!res.ok()) {
      TRY2(close_all_cpu());
      return res;
    }
  }
  return StatusTuple::OK();
}

StatusTuple BPFPerfEventArray::close_all_cpu() {
  std::string errors;
  bool has_error = false;

  std::vector<int> opened_cpus;
  for (auto it : cpu_fds_)
    opened_cpus.push_back(it.first);
  for (int i : opened_cpus) {
    auto res = close_on_cpu(i);
    if (!res.ok()) {
      errors += "Failed to close CPU" + std::to_string(i) + " perf event: ";
      errors += res.msg() + "\n";
      has_error = true;
    }
  }

  if (has_error)
    return StatusTuple(-1, errors);
  return StatusTuple::OK();
}

StatusTuple BPFPerfEventArray::open_on_cpu(int cpu, uint32_t type,
                                           uint64_t config, int pid) {
  if (cpu_fds_.find(cpu) != cpu_fds_.end())
    return StatusTuple(-1, "Perf event already open on CPU %d", cpu);
  int fd = bpf_open_perf_event(type, config, pid, cpu);
  if (fd < 0) {
    return StatusTuple(-1, "Error constructing perf event %" PRIu32 ":%" PRIu64,
                       type, config);
  }
  if (!update(&cpu, &fd)) {
    bpf_close_perf_event_fd(fd);
    return StatusTuple(-1, "Unable to open perf event on CPU %d: %s", cpu,
                       std::strerror(errno));
  }
  cpu_fds_[cpu] = fd;
  return StatusTuple::OK();
}

StatusTuple BPFPerfEventArray::close_on_cpu(int cpu) {
  auto it = cpu_fds_.find(cpu);
  if (it == cpu_fds_.end()) {
    return StatusTuple::OK();
  }
  bpf_close_perf_event_fd(it->second);
  cpu_fds_.erase(it);
  return StatusTuple::OK();
}

BPFPerfEventArray::~BPFPerfEventArray() {
  auto res = close_all_cpu();
  if (!res.ok()) {
    std::cerr << "Failed to close all perf buffer on destruction: " << res.msg()
              << std::endl;
  }
}

BPFProgTable::BPFProgTable(const TableDesc& desc)
    : BPFTableBase<int, int>(desc) {
  if (desc.type != BPF_MAP_TYPE_PROG_ARRAY)
    throw std::invalid_argument("Table '" + desc.name +
                                "' is not a prog table");
}

StatusTuple BPFProgTable::update_value(const int& index, const int& prog_fd) {
  if (!this->update(const_cast<int*>(&index), const_cast<int*>(&prog_fd)))
    return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
  return StatusTuple::OK();
}

StatusTuple BPFProgTable::remove_value(const int& index) {
  if (!this->remove(const_cast<int*>(&index)))
    return StatusTuple(-1, "Error removing value: %s", std::strerror(errno));
  return StatusTuple::OK();
}

BPFCgroupArray::BPFCgroupArray(const TableDesc& desc)
    : BPFTableBase<int, int>(desc) {
  if (desc.type != BPF_MAP_TYPE_CGROUP_ARRAY)
    throw std::invalid_argument("Table '" + desc.name +
                                "' is not a cgroup array");
}

StatusTuple BPFCgroupArray::update_value(const int& index,
                                         const int& cgroup2_fd) {
  if (!this->update(const_cast<int*>(&index), const_cast<int*>(&cgroup2_fd)))
    return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
  return StatusTuple::OK();
}

StatusTuple BPFCgroupArray::update_value(const int& index,
                                         const std::string& cgroup2_path) {
  FileDesc f(::open(cgroup2_path.c_str(), O_RDONLY | O_CLOEXEC));
  if ((int)f < 0)
    return StatusTuple(-1, "Unable to open %s", cgroup2_path.c_str());
  TRY2(update_value(index, (int)f));
  return StatusTuple::OK();
}

StatusTuple BPFCgroupArray::remove_value(const int& index) {
  if (!this->remove(const_cast<int*>(&index)))
    return StatusTuple(-1, "Error removing value: %s", std::strerror(errno));
  return StatusTuple::OK();
}

BPFDevmapTable::BPFDevmapTable(const TableDesc& desc)
    : BPFTableBase<int, int>(desc) {
    if(desc.type != BPF_MAP_TYPE_DEVMAP)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a devmap table");
}

StatusTuple BPFDevmapTable::update_value(const int& index,
                                         const int& value) {
    if (!this->update(const_cast<int*>(&index), const_cast<int*>(&value)))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple::OK();
}

StatusTuple BPFDevmapTable::get_value(const int& index,
                                      int& value) {
    if (!this->lookup(const_cast<int*>(&index), &value))
      return StatusTuple(-1, "Error getting value: %s", std::strerror(errno));
    return StatusTuple::OK();
}

StatusTuple BPFDevmapTable::remove_value(const int& index) {
    if (!this->remove(const_cast<int*>(&index)))
      return StatusTuple(-1, "Error removing value: %s", std::strerror(errno));
    return StatusTuple::OK();
}

BPFXskmapTable::BPFXskmapTable(const TableDesc& desc)
    : BPFTableBase<int, int>(desc) {
    if(desc.type != BPF_MAP_TYPE_XSKMAP)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a xskmap table");
}

StatusTuple BPFXskmapTable::update_value(const int& index,
                                         const int& value) {
    if (!this->update(const_cast<int*>(&index), const_cast<int*>(&value)))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple::OK();
}

StatusTuple BPFXskmapTable::get_value(const int& index,
                                      int& value) {
    if (!this->lookup(const_cast<int*>(&index), &value))
      return StatusTuple(-1, "Error getting value: %s", std::strerror(errno));
    return StatusTuple::OK();
}

StatusTuple BPFXskmapTable::remove_value(const int& index) {
    if (!this->remove(const_cast<int*>(&index)))
      return StatusTuple(-1, "Error removing value: %s", std::strerror(errno));
    return StatusTuple::OK();
}

BPFSockmapTable::BPFSockmapTable(const TableDesc& desc)
    : BPFTableBase<int, int>(desc) {
    if(desc.type != BPF_MAP_TYPE_SOCKMAP)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a sockmap table");
}

StatusTuple BPFSockmapTable::update_value(const int& index,
                                         const int& value) {
    if (!this->update(const_cast<int*>(&index), const_cast<int*>(&value)))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple::OK();
}

StatusTuple BPFSockmapTable::remove_value(const int& index) {
    if (!this->remove(const_cast<int*>(&index)))
      return StatusTuple(-1, "Error removing value: %s", std::strerror(errno));
    return StatusTuple::OK();
}

BPFSockhashTable::BPFSockhashTable(const TableDesc& desc)
    : BPFTableBase<int, int>(desc) {
    if(desc.type != BPF_MAP_TYPE_SOCKHASH)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a sockhash table");
}

StatusTuple BPFSockhashTable::update_value(const int& key,
                                         const int& value) {
    if (!this->update(const_cast<int*>(&key), const_cast<int*>(&value)))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple::OK();
}

StatusTuple BPFSockhashTable::remove_value(const int& key) {
    if (!this->remove(const_cast<int*>(&key)))
      return StatusTuple(-1, "Error removing value: %s", std::strerror(errno));
    return StatusTuple::OK();
}

}  // namespace ebpf
