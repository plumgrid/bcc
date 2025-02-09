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

#pragma once

#include <errno.h>
#include <sys/epoll.h>
#include <cstring>
#include <exception>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "bcc_exception.h"
#include "bcc_syms.h"
#include "bpf_module.h"
#include "libbpf.h"
#include "perf_reader.h"
#include "table_desc.h"
#include "linux/bpf.h"

namespace ebpf {

constexpr static size_t MAX_BATCH_SIZE = 128;

template<class ValueType>
class BPFQueueStackTableBase {
 public:
  size_t capacity() const { return desc.max_entries; }

  StatusTuple string_to_leaf(const std::string& value_str, ValueType* value) {
    return desc.leaf_sscanf(value_str.c_str(), value);
  }

  StatusTuple leaf_to_string(const ValueType* value, std::string& value_str) {
    char buf[8 * desc.leaf_size];
    StatusTuple rc = desc.leaf_snprintf(buf, sizeof(buf), value);
    if (rc.ok())
      value_str.assign(buf);
    return rc;
  }

  int get_fd() { return desc.fd; }

 protected:
  explicit BPFQueueStackTableBase(const TableDesc& desc);

  bool pop(void *value) {
    return bpf_lookup_and_delete(desc.fd, nullptr, value) >= 0;
  }
  // Flags are extremely useful, since they completely changes extraction behaviour
  // (eg. if flag BPF_EXIST, then if the queue/stack is full remove the oldest one)
  bool push(void *value, unsigned long long int flags) {
    return bpf_update_elem(desc.fd, nullptr, value, flags) >= 0;
  }

  bool peek(void *value) {
    return bpf_lookup_elem(desc.fd, nullptr, value) >= 0;
  }

  const TableDesc& desc;
};

template <>
inline BPFQueueStackTableBase<void>::BPFQueueStackTableBase(
    const TableDesc& desc) : desc(desc) {}

template <class ValueType>
inline BPFQueueStackTableBase<ValueType>::BPFQueueStackTableBase(
    const TableDesc& desc) : desc(desc) {
  if (desc.leaf_size != sizeof(ValueType)) {
    throw std::invalid_argument("Table '" + desc.name +
                                "' is ValueType is illegal");
  }
}

template <class KeyType, class ValueType>
class BPFTableBase {
 public:
  size_t capacity() { return desc.max_entries; }

  StatusTuple string_to_key(const std::string& key_str, KeyType* key) {
    return desc.key_sscanf(key_str.c_str(), key);
  }

  StatusTuple string_to_leaf(const std::string& value_str, ValueType* value) {
    return desc.leaf_sscanf(value_str.c_str(), value);
  }

  StatusTuple key_to_string(const KeyType* key, std::string& key_str) {
    char buf[8 * desc.key_size];
    StatusTuple rc = desc.key_snprintf(buf, sizeof(buf), key);
    if (rc.ok())
      key_str.assign(buf);
    return rc;
  }

  StatusTuple leaf_to_string(const ValueType* value, std::string& value_str) {
    char buf[8 * desc.leaf_size];
    StatusTuple rc = desc.leaf_snprintf(buf, sizeof(buf), value);
    if (rc.ok())
      value_str.assign(buf);
    return rc;
  }

  int get_fd() {
    return desc.fd;
  }

 protected:
  template <class T>
  struct is_vector {
    static constexpr bool value = false;
  };

  template <class T>
  struct is_vector<std::vector<T>> {
    static constexpr bool value = true;
  };

  template <typename T = ValueType>
  explicit BPFTableBase(const typename std::enable_if<is_vector<T>::value, TableDesc>::type& desc);

  template <typename T = ValueType>
  explicit BPFTableBase(const typename std::enable_if<!is_vector<T>::value, TableDesc>::type& desc);

  bool lookup(void* key, void* value) {
    return bpf_lookup_elem(desc.fd, key, value) >= 0;
  }

  int64_t lookup_batch(void* keys, void* values, void** cursor, const size_t count) {
    __u32 out;
    __u32 n, n_read = 0;
    int err = 0;

    while (n_read < count && !err) {
      n = count - n_read;
      auto* in = static_cast<__u32*>(*cursor);
      err = bpf_lookup_batch(desc.fd, in, &out,
                             static_cast<char*>(keys) + n_read * desc.key_size,
                             static_cast<char*>(values) + n_read * desc.leaf_size,
                             &n);
      if (err && errno != ENOENT) {
        return -1;
      }
      n_read += n;
      if (in != nullptr)
        *in = out;
    }

    return n_read;
  }

  bool first(void* key) {
    return bpf_get_first_key(desc.fd, key, desc.key_size) >= 0;
  }

  bool next(void* key, void* next_key) {
    return bpf_get_next_key(desc.fd, key, next_key) >= 0;
  }

  bool update(void* key, void* value) {
    return bpf_update_elem(desc.fd, key, value, 0) >= 0;
  }

  bool remove(void* key) { return bpf_delete_elem(desc.fd, key) >= 0; }

  const TableDesc& desc;
};
template <>
template <typename T>
BPFTableBase<void, void>::BPFTableBase(const typename std::enable_if<is_vector<T>::value, TableDesc>::type& desc) {}

template <>
template <typename T>
inline BPFTableBase<void, void>::BPFTableBase(const typename std::enable_if<!is_vector<T>::value, TableDesc>::type& desc) : desc(desc) {}

template <class KeyType, class ValueType>
template <typename T>
inline BPFTableBase<KeyType, ValueType>::BPFTableBase(const typename std::enable_if<is_vector<T>::value, TableDesc>::type& desc) : desc(desc) {
  if (desc.type == BPF_MAP_TYPE_PERCPU_ARRAY || desc.type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
      || desc.type == BPF_MAP_TYPE_LRU_PERCPU_HASH || desc.type == BPF_MAP_TYPE_PERCPU_HASH) {
    if (desc.leaf_size != sizeof(typename ValueType::value_type)) {
      throw std::invalid_argument(
          "Table '" + desc.name +
          "' is ValueType is illegal: desc.leaf_size: " +
          std::to_string(desc.leaf_size) +
          " != sizeof(typename ValueType::value_type): " +
          std::to_string(sizeof(typename ValueType::value_type)));
    }
  } else {
    if (desc.leaf_size != sizeof(ValueType)) {
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is ValueType is illegal: desc.leaf_size: "
                                  + std::to_string(desc.leaf_size) + " != sizeof(ValueType): "
                                  + std::to_string(sizeof(ValueType)));
    }
  }

  if (desc.key_size != sizeof(KeyType)) {
    throw std::invalid_argument("Table '" + desc.name +
                                "' is KeyType is illegal");
  }
}

template <class KeyType, class ValueType>
template <typename T>
inline BPFTableBase<KeyType, ValueType>::BPFTableBase(const typename std::enable_if<!is_vector<T>::value, TableDesc>::type& desc) : desc(desc) {
  if (desc.leaf_size != sizeof(ValueType)) {
    throw std::invalid_argument("Table '" + desc.name +
                                "' is ValueType is illegal: desc.leaf_size: "
                                + std::to_string(desc.leaf_size) + " != sizeof(ValueType): "
                                + std::to_string(sizeof(ValueType)));
  }
  if (desc.key_size != sizeof(KeyType)) {
    throw std::invalid_argument("Table '" + desc.name +
                                "' is KeyType is illegal");
  }
}

class BPFTable : public BPFTableBase<void, void> {
 public:
  BPFTable(const TableDesc& desc);

  StatusTuple get_value(const std::string& key_str, std::string& value);
  StatusTuple get_value(const std::string& key_str,
                        std::vector<std::string>& value);

  StatusTuple update_value(const std::string& key_str,
                           const std::string& value_str);
  StatusTuple update_value(const std::string& key_str,
                           const std::vector<std::string>& value_str);

  StatusTuple remove_value(const std::string& key_str);

  StatusTuple clear_table_non_atomic();
  StatusTuple get_table_offline(std::vector<std::pair<std::string, std::string>> &res);

  static size_t get_possible_cpu_count();
};

template <class ValueType>
void* get_value_addr(ValueType& t) {
  return &t;
}

template <class ValueType>
void* get_value_addr(std::vector<ValueType>& t) {
  return t.data();
}

template<class ValueType>
class BPFQueueStackTable : public BPFQueueStackTableBase<void> {
 public:
  explicit BPFQueueStackTable(const TableDesc& desc) : BPFQueueStackTableBase(desc) {
    if (desc.type != BPF_MAP_TYPE_QUEUE &&
        desc.type != BPF_MAP_TYPE_STACK)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a queue/stack table");
  }

  virtual StatusTuple pop_value(ValueType& value) {
    if (!this->pop(get_value_addr(value)))
      return StatusTuple(-1, "Error getting value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  virtual StatusTuple push_value(const ValueType& value, unsigned long long int flags = 0) {
    if (!this->push(get_value_addr(const_cast<ValueType&>(value)), flags))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  virtual StatusTuple get_head(const ValueType& value) {
    if (!this->peek(get_value_addr(const_cast<ValueType&>(value))))
      return StatusTuple(-1, "Error peeking value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }
};

template <class ValueType>
class BPFArrayTable : public BPFTableBase<int, ValueType> {
 public:
  BPFArrayTable(const TableDesc& desc) : BPFTableBase<int, ValueType>(desc) {
    if (desc.type != BPF_MAP_TYPE_ARRAY &&
        desc.type != BPF_MAP_TYPE_PERCPU_ARRAY)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not an array table");
  }

  virtual StatusTuple get_value(const int& index, ValueType& value) {
    if (!this->lookup(const_cast<int*>(&index), get_value_addr(value)))
      return StatusTuple(-1, "Error getting value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  virtual StatusTuple update_value(const int& index, const ValueType& value) {
    if (!this->update(const_cast<int*>(&index),
                      get_value_addr(const_cast<ValueType&>(value))))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  ValueType operator[](const int& key) {
    ValueType value;
    get_value(key, value);
    return value;
  }

  std::vector<ValueType> get_table_offline() {
    std::vector<ValueType> res(this->capacity());

    for (int i = 0; i < (int)this->capacity(); i++) {
      get_value(i, res[i]);
    }

    return res;
  }
};

template <class ValueType>
class BPFPercpuArrayTable : public BPFArrayTable<std::vector<ValueType>> {
 public:
  BPFPercpuArrayTable(const TableDesc& desc)
      : BPFArrayTable<std::vector<ValueType>>(desc),
        ncpus(BPFTable::get_possible_cpu_count()) {
    if (desc.type != BPF_MAP_TYPE_PERCPU_ARRAY)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a percpu array table");
    // leaf structures have to be aligned to 8 bytes as hardcoded in the linux
    // kernel.
    if (sizeof(ValueType) % 8)
      throw std::invalid_argument("leaf must be aligned to 8 bytes");
  }

  StatusTuple get_value(const int& index, std::vector<ValueType>& value) {
    value.resize(ncpus);
    return BPFArrayTable<std::vector<ValueType>>::get_value(index, value);
  }

  StatusTuple update_value(const int& index,
                           const std::vector<ValueType>& value) {
    if (value.size() != ncpus)
      return StatusTuple(-1, "bad value size");
    return BPFArrayTable<std::vector<ValueType>>::update_value(index, value);
  }

 private:
  unsigned int ncpus;
};

template <class KeyType, class ValueType>
class BPFHashTable : public BPFTableBase<KeyType, ValueType> {
 public:
  explicit BPFHashTable(const TableDesc& desc)
      : BPFTableBase<KeyType, ValueType>(desc) {
    if (desc.type != BPF_MAP_TYPE_HASH &&
        desc.type != BPF_MAP_TYPE_PERCPU_HASH &&
        desc.type != BPF_MAP_TYPE_LRU_HASH &&
        desc.type != BPF_MAP_TYPE_LRU_PERCPU_HASH)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a hash table");
  }

  virtual StatusTuple get_value(const KeyType& key, ValueType& value) {
    if (!this->lookup(const_cast<KeyType*>(&key), get_value_addr(value)))
      return StatusTuple(-1, "Error getting value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  virtual StatusTuple update_value(const KeyType& key, const ValueType& value) {
    if (!this->update(const_cast<KeyType*>(&key),
                      get_value_addr(const_cast<ValueType&>(value))))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  virtual StatusTuple remove_value(const KeyType& key) {
    if (!this->remove(const_cast<KeyType*>(&key)))
      return StatusTuple(-1, "Error removing value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  ValueType operator[](const KeyType& key) {
    ValueType value;
    get_value(key, value);
    return value;
  }

  std::vector<std::pair<KeyType, ValueType>> get_table_offline() {
    std::vector<std::pair<KeyType, ValueType>> res;
    size_t batch_size = std::min(MAX_BATCH_SIZE, this->capacity());
    std::unique_ptr<KeyType[]> keys = std::make_unique<KeyType[]>(batch_size);
    std::unique_ptr<ValueType[]> values = std::make_unique<ValueType[]>(batch_size);

    void* cursor = nullptr;

    while (true) {
      int64_t r = this->lookup_batch(keys.get(), values.get(), &cursor, batch_size);
      if (r < 0) {
        throw std::system_error(errno, std::generic_category(), "lookup_batch");
      }

      for (size_t i = 0; i < r; ++i) {
        res.emplace_back(keys[i], values[i]);
      }

      if (r < batch_size)
        break;
    }

    return res;
  }

  StatusTuple clear_table_non_atomic() {
    KeyType cur;
    while (this->first(&cur))
      TRY2(remove_value(cur));

    return StatusTuple::OK();
  }
};

template <class KeyType, class ValueType>
class BPFPercpuHashTable
    : public BPFHashTable<KeyType, std::vector<ValueType>> {
 public:
  explicit BPFPercpuHashTable(const TableDesc& desc)
      : BPFHashTable<KeyType, std::vector<ValueType>>(desc),
        ncpus(BPFTable::get_possible_cpu_count()) {
    if (desc.type != BPF_MAP_TYPE_PERCPU_HASH &&
        desc.type != BPF_MAP_TYPE_LRU_PERCPU_HASH)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a percpu hash table");
    // leaf structures have to be aligned to 8 bytes as hardcoded in the linux
    // kernel.
    if (sizeof(ValueType) % 8)
      throw std::invalid_argument("leaf must be aligned to 8 bytes");
  }

  StatusTuple get_value(const KeyType& key, std::vector<ValueType>& value) {
    value.resize(ncpus);
    return BPFHashTable<KeyType, std::vector<ValueType>>::get_value(key, value);
  }

  StatusTuple update_value(const KeyType& key,
                           const std::vector<ValueType>& value) {
    if (value.size() != ncpus)
      return StatusTuple(-1, "bad value size");
    return BPFHashTable<KeyType, std::vector<ValueType>>::update_value(key,
                                                                       value);
  }

 private:
  unsigned int ncpus;
};

// From src/cc/export/helpers.h
static const int BPF_MAX_STACK_DEPTH = 127;
struct stacktrace_t {
  uintptr_t ip[BPF_MAX_STACK_DEPTH];
};

class BPFStackTable : public BPFTableBase<int, stacktrace_t> {
 public:
  BPFStackTable(const TableDesc& desc, bool use_debug_file,
                bool check_debug_file_crc);
  BPFStackTable(BPFStackTable&& that);
  ~BPFStackTable();

  void free_symcache(int pid);
  void clear_table_non_atomic();
  std::vector<uintptr_t> get_stack_addr(int stack_id);
  std::vector<std::string> get_stack_symbol(int stack_id, int pid);

 private:
  bcc_symbol_option symbol_option_;
  std::map<int, void*> pid_sym_;
};

// from src/cc/export/helpers.h
struct stacktrace_buildid_t {
  struct bpf_stack_build_id trace[BPF_MAX_STACK_DEPTH];
};

class BPFStackBuildIdTable : public BPFTableBase<int, stacktrace_buildid_t> {
 public:
  BPFStackBuildIdTable(const TableDesc& desc, bool use_debug_file,
                       bool check_debug_file_crc, void *bsymcache);
  ~BPFStackBuildIdTable() = default;

  void clear_table_non_atomic();
  std::vector<bpf_stack_build_id> get_stack_addr(int stack_id);
  std::vector<std::string> get_stack_symbol(int stack_id);

 private:
  void *bsymcache_;
  bcc_symbol_option symbol_option_;
};

class BPFPerfBuffer : public BPFTableBase<int, int> {
 public:
  BPFPerfBuffer(const TableDesc& desc);
  ~BPFPerfBuffer();

  StatusTuple open_all_cpu(perf_reader_raw_cb cb, perf_reader_lost_cb lost_cb,
                           void* cb_cookie, int page_cnt);
  StatusTuple open_all_cpu(perf_reader_raw_cb cb, perf_reader_lost_cb lost_cb,
                           void* cb_cookie, int page_cnt, int wakeup_events);
  StatusTuple close_all_cpu();
  int poll(int timeout_ms);
  int consume();

 private:
  StatusTuple open_on_cpu(perf_reader_raw_cb cb, perf_reader_lost_cb lost_cb,
                          void* cb_cookie, int page_cnt, struct bcc_perf_buffer_opts& opts);
  StatusTuple close_on_cpu(int cpu);

  std::map<int, perf_reader*> cpu_readers_;

  int epfd_;
  std::unique_ptr<epoll_event[]> ep_events_;
};

class BPFPerfEventArray : public BPFTableBase<int, int> {
 public:
  BPFPerfEventArray(const TableDesc& desc);
  ~BPFPerfEventArray();

  StatusTuple open_all_cpu(uint32_t type, uint64_t config, int pid = -1);
  StatusTuple close_all_cpu();

 private:
  StatusTuple open_on_cpu(int cpu, uint32_t type, uint64_t config, int pid = -1);
  StatusTuple close_on_cpu(int cpu);

  std::map<int, int> cpu_fds_;
};

class BPFProgTable : public BPFTableBase<int, int> {
 public:
  BPFProgTable(const TableDesc& desc);

  StatusTuple update_value(const int& index, const int& prog_fd);
  StatusTuple remove_value(const int& index);
};

class BPFCgroupArray : public BPFTableBase<int, int> {
 public:
  BPFCgroupArray(const TableDesc& desc);

  StatusTuple update_value(const int& index, const int& cgroup2_fd);
  StatusTuple update_value(const int& index, const std::string& cgroup2_path);
  StatusTuple remove_value(const int& index);
};

class BPFDevmapTable : public BPFTableBase<int, int> {
public:
  BPFDevmapTable(const TableDesc& desc);

  StatusTuple update_value(const int& index, const int& value);
  StatusTuple get_value(const int& index, int& value);
  StatusTuple remove_value(const int& index);
};

class BPFXskmapTable : public BPFTableBase<int, int> {
public:
  BPFXskmapTable(const TableDesc& desc);

  StatusTuple update_value(const int& index, const int& value);
  StatusTuple get_value(const int& index, int& value);
  StatusTuple remove_value(const int& index);
};

template <class KeyType>
class BPFMapInMapTable : public BPFTableBase<KeyType, int> {
 public:
  BPFMapInMapTable(const TableDesc& desc) : BPFTableBase<KeyType, int>(desc) {
    if (desc.type != BPF_MAP_TYPE_ARRAY_OF_MAPS &&
        desc.type != BPF_MAP_TYPE_HASH_OF_MAPS)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a map-in-map table");
  }
  virtual StatusTuple update_value(const KeyType& key, const int& inner_map_fd) {
    if (!this->update(const_cast<KeyType*>(&key),
                      const_cast<int*>(&inner_map_fd)))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }
  virtual StatusTuple remove_value(const KeyType& key) {
    if (!this->remove(const_cast<KeyType*>(&key)))
      return StatusTuple(-1, "Error removing value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }
};

class BPFSockmapTable : public BPFTableBase<int, int> {
public:
  BPFSockmapTable(const TableDesc& desc);

  StatusTuple update_value(const int& index, const int& value);
  StatusTuple remove_value(const int& index);
};

class BPFSockhashTable : public BPFTableBase<int, int> {
public:
  BPFSockhashTable(const TableDesc& desc);

  StatusTuple update_value(const int& key, const int& value);
  StatusTuple remove_value(const int& key);
};

template <class ValueType>
class BPFSkStorageTable : public BPFTableBase<int, ValueType> {
 public:
  BPFSkStorageTable(const TableDesc& desc) : BPFTableBase<int, ValueType>(desc) {
    if (desc.type != BPF_MAP_TYPE_SK_STORAGE)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a sk_storage table");
  }

  virtual StatusTuple get_value(const int& sock_fd, ValueType& value) {
    if (!this->lookup(const_cast<int*>(&sock_fd), get_value_addr(value)))
      return StatusTuple(-1, "Error getting value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  virtual StatusTuple update_value(const int& sock_fd, const ValueType& value) {
    if (!this->update(const_cast<int*>(&sock_fd),
                      get_value_addr(const_cast<ValueType&>(value))))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  virtual StatusTuple remove_value(const int& sock_fd) {
    if (!this->remove(const_cast<int*>(&sock_fd)))
      return StatusTuple(-1, "Error removing value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }
};

template <class ValueType>
class BPFInodeStorageTable : public BPFTableBase<int, ValueType> {
 public:
  BPFInodeStorageTable(const TableDesc& desc) : BPFTableBase<int, ValueType>(desc) {
    if (desc.type != BPF_MAP_TYPE_INODE_STORAGE)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a inode_storage table");
  }

  virtual StatusTuple get_value(const int& fd, ValueType& value) {
    if (!this->lookup(const_cast<int*>(&fd), get_value_addr(value)))
      return StatusTuple(-1, "Error getting value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  virtual StatusTuple update_value(const int& fd, const ValueType& value) {
    if (!this->update(const_cast<int*>(&fd),
                      get_value_addr(const_cast<ValueType&>(value))))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  virtual StatusTuple remove_value(const int& fd) {
    if (!this->remove(const_cast<int*>(&fd)))
      return StatusTuple(-1, "Error removing value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }
};

template <class ValueType>
class BPFTaskStorageTable : public BPFTableBase<int, ValueType> {
 public:
  BPFTaskStorageTable(const TableDesc& desc) : BPFTableBase<int, ValueType>(desc) {
    if (desc.type != BPF_MAP_TYPE_TASK_STORAGE)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a task_storage table");
  }

  virtual StatusTuple get_value(const int& fd, ValueType& value) {
    if (!this->lookup(const_cast<int*>(&fd), get_value_addr(value)))
      return StatusTuple(-1, "Error getting value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  virtual StatusTuple update_value(const int& fd, const ValueType& value) {
    if (!this->update(const_cast<int*>(&fd),
                      get_value_addr(const_cast<ValueType&>(value))))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  virtual StatusTuple remove_value(const int& fd) {
    if (!this->remove(const_cast<int*>(&fd)))
      return StatusTuple(-1, "Error removing value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }
};

template <class ValueType>
class BPFCgStorageTable : public BPFTableBase<int, ValueType> {
 public:
  BPFCgStorageTable(const TableDesc& desc) : BPFTableBase<int, ValueType>(desc) {
    if (desc.type != BPF_MAP_TYPE_CGROUP_STORAGE)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a cgroup_storage table");
  }

  virtual StatusTuple get_value(struct bpf_cgroup_storage_key& key,
                                ValueType& value) {
    if (!this->lookup(const_cast<struct bpf_cgroup_storage_key*>(&key),
                      get_value_addr(value)))
      return StatusTuple(-1, "Error getting value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  virtual StatusTuple update_value(struct bpf_cgroup_storage_key& key, const ValueType& value) {
    if (!this->update(const_cast<struct bpf_cgroup_storage_key*>(&key),
                      get_value_addr(const_cast<ValueType&>(value))))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }
};

template <class ValueType>
class BPFPercpuCgStorageTable : public BPFTableBase<int, std::vector<ValueType>> {
 public:
  BPFPercpuCgStorageTable(const TableDesc& desc)
      : BPFTableBase<int, std::vector<ValueType>>(desc) {
    if (desc.type != BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a percpu_cgroup_storage table");
    if (sizeof(ValueType) % 8)
      throw std::invalid_argument("leaf must be aligned to 8 bytes");
    ncpus = BPFTable::get_possible_cpu_count();
  }

  virtual StatusTuple get_value(struct bpf_cgroup_storage_key& key,
                                std::vector<ValueType>& value) {
    value.resize(ncpus);
    if (!this->lookup(const_cast<struct bpf_cgroup_storage_key*>(&key),
                      get_value_addr(value)))
      return StatusTuple(-1, "Error getting value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }

  virtual StatusTuple update_value(struct bpf_cgroup_storage_key& key,
                                   std::vector<ValueType>& value) {
    value.resize(ncpus);
    if (!this->update(const_cast<struct bpf_cgroup_storage_key*>(&key),
                      get_value_addr(const_cast<std::vector<ValueType>&>(value))))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple::OK();
  }
 private:
  unsigned int ncpus;
};

}  // namespace ebpf
