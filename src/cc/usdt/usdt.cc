/*
 * Copyright (c) 2016 GitHub, Inc.
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
#include <algorithm>
#include <cstring>
#include <sstream>
#include <unordered_set>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bcc_elf.h"
#include "bcc_proc.h"
#include "common.h"
#include "usdt.h"
#include "vendor/tinyformat.hpp"
#include "bcc_usdt.h"

namespace USDT {

Location::Location(uint64_t addr, const std::string &bin_path, const char *arg_fmt)
    : address_(addr),
      bin_path_(bin_path) {

#ifdef __aarch64__
  ArgumentParser_aarch64 parser(arg_fmt);
#elif __powerpc64__
  ArgumentParser_powerpc64 parser(arg_fmt);
#else
  ArgumentParser_x64 parser(arg_fmt);
#endif
  while (!parser.done()) {
    Argument arg;
    if (!parser.parse(&arg))
      continue;
    arguments_.push_back(std::move(arg));
  }
}

Probe::Probe(const char *bin_path, const char *provider, const char *name,
             uint64_t semaphore, const optional<int> &pid, ProcMountNS *ns)
    : bin_path_(bin_path),
      provider_(provider),
      name_(name),
      semaphore_(semaphore),
      pid_(pid),
      mount_ns_(ns) {}

bool Probe::in_shared_object(const std::string &bin_path) {
    if (object_type_map_.find(bin_path) == object_type_map_.end()) {
      ProcMountNSGuard g(mount_ns_);
      return (object_type_map_[bin_path] = bcc_elf_is_shared_obj(bin_path.c_str()));
    }
    return object_type_map_[bin_path];
}

bool Probe::resolve_global_address(uint64_t *global, const std::string &bin_path,
                                   const uint64_t addr) {
  if (in_shared_object(bin_path)) {
    return (pid_ &&
            !bcc_resolve_global_addr(*pid_, bin_path.c_str(), addr, global));
  }

  *global = addr;
  return true;
}

bool Probe::add_to_semaphore(int16_t val) {
  assert(pid_);

  if (!attached_semaphore_) {
    uint64_t addr;
    if (!resolve_global_address(&addr, bin_path_, semaphore_))
      return false;
    attached_semaphore_ = addr;
  }

  off_t address = static_cast<off_t>(attached_semaphore_.value());

  std::string procmem = tfm::format("/proc/%d/mem", pid_.value());
  int memfd = ::open(procmem.c_str(), O_RDWR);
  if (memfd < 0)
    return false;

  int16_t original;

  if (::lseek(memfd, address, SEEK_SET) < 0 ||
      ::read(memfd, &original, 2) != 2) {
    ::close(memfd);
    return false;
  }

  original = original + val;

  if (::lseek(memfd, address, SEEK_SET) < 0 ||
      ::write(memfd, &original, 2) != 2) {
    ::close(memfd);
    return false;
  }

  ::close(memfd);
  return true;
}

bool Probe::enable(const std::string &fn_name) {
  if (attached_to_)
    return false;

  if (need_enable()) {
    if (!pid_)
      return false;

    if (!add_to_semaphore(+1))
      return false;
  }

  attached_to_ = fn_name;
  return true;
}

bool Probe::disable() {
  if (!attached_to_)
    return false;

  attached_to_ = nullopt;

  if (need_enable()) {
    assert(pid_);
    return add_to_semaphore(-1);
  }
  return true;
}

std::string Probe::largest_arg_type(size_t arg_n) {
  Argument *largest = nullptr;
  for (Location &location : locations_) {
    Argument *candidate = &location.arguments_[arg_n];
    if (!largest ||
        std::abs(candidate->arg_size()) > std::abs(largest->arg_size()))
      largest = candidate;
  }

  assert(largest);
  return largest->ctype();
}

bool Probe::usdt_getarg(std::ostream &stream) {
  if (!attached_to_.has_value() || attached_to_.value().empty())
    return false;

  return usdt_getarg(stream, attached_to_.value());
}

bool Probe::usdt_getarg(std::ostream &stream, const std::string& probe_func) {
  const size_t arg_count = locations_[0].arguments_.size();

  if (arg_count == 0)
    return true;

  for (size_t arg_n = 0; arg_n < arg_count; ++arg_n) {
    std::string ctype = largest_arg_type(arg_n);
    std::string cptr = tfm::format("*((%s *)dest)", ctype);

    tfm::format(stream,
                "static __always_inline int _bpf_readarg_%s_%d("
                "struct pt_regs *ctx, void *dest, size_t len) {\n"
                "  if (len != sizeof(%s)) return -1;\n",
                probe_func, arg_n + 1, ctype);

    if (locations_.size() == 1) {
      Location &location = locations_.front();
      stream << "  ";
      if (!location.arguments_[arg_n].assign_to_local(stream, cptr, location.bin_path_,
                                                      pid_))
        return false;
      stream << "\n  return 0;\n}\n";
    } else {
      stream << "  switch(PT_REGS_IP(ctx)) {\n";
      for (Location &location : locations_) {
        uint64_t global_address;

        if (!resolve_global_address(&global_address, location.bin_path_,
                                    location.address_))
          return false;

        tfm::format(stream, "  case 0x%xULL: ", global_address);
        if (!location.arguments_[arg_n].assign_to_local(stream, cptr, location.bin_path_,
                                                        pid_))
          return false;

        stream << " return 0;\n";
      }
      stream << "  }\n";
      stream << "  return -1;\n}\n";
    }
  }
  return true;
}

void Probe::add_location(uint64_t addr, const std::string &bin_path, const char *fmt) {
  locations_.emplace_back(addr, bin_path, fmt);
}

void Probe::finalize_locations() {
  std::sort(locations_.begin(), locations_.end(),
            [](const Location &a, const Location &b) {
              return a.bin_path_ < b.bin_path_ || a.address_ < b.address_;
            });
  auto last = std::unique(locations_.begin(), locations_.end(),
                          [](const Location &a, const Location &b) {
                            return a.bin_path_ == b.bin_path_ && a.address_ == b.address_;
                          });
  locations_.erase(last, locations_.end());
}

void Context::_each_probe(const char *binpath, const struct bcc_elf_usdt *probe,
                          void *p) {
  Context *ctx = static_cast<Context *>(p);
  ctx->add_probe(binpath, probe);
}

int Context::_each_module(const char *modpath, uint64_t, uint64_t, uint64_t,
                          bool, void *p) {
  Context *ctx = static_cast<Context *>(p);
  // Modules may be reported multiple times if they contain more than one
  // executable region. We are going to parse the ELF on disk anyway, so we
  // don't need these duplicates.
  if (ctx->modules_.insert(modpath).second /*inserted new?*/) {
    ProcMountNSGuard g(ctx->mount_ns_instance_.get());
    bcc_elf_foreach_usdt(modpath, _each_probe, p);
  }
  return 0;
}

void Context::add_probe(const char *binpath, const struct bcc_elf_usdt *probe) {
  for (auto &p : probes_) {
    if (p->provider_ == probe->provider && p->name_ == probe->name) {
      p->add_location(probe->pc, binpath, probe->arg_fmt);
      return;
    }
  }

  probes_.emplace_back(
      new Probe(binpath, probe->provider, probe->name, probe->semaphore, pid_,
	mount_ns_instance_.get()));
  probes_.back()->add_location(probe->pc, binpath, probe->arg_fmt);
}

std::string Context::resolve_bin_path(const std::string &bin_path) {
  std::string result;

  if (char *which = bcc_procutils_which(bin_path.c_str())) {
    result = which;
    ::free(which);
  } else if (char *which_so = bcc_procutils_which_so(bin_path.c_str(), 0)) {
    result = which_so;
    ::free(which_so);
  }

  return result;
}

Probe *Context::get(const std::string &probe_name) {
  for (auto &p : probes_) {
    if (p->name_ == probe_name)
      return p.get();
  }
  return nullptr;
}

Probe *Context::get(const std::string &provider_name,
                    const std::string &probe_name) {
  for (auto &p : probes_) {
    if (p->provider_ == provider_name && p->name_ == probe_name)
      return p.get();
  }
  return nullptr;
}

bool Context::enable_probe(const std::string &probe_name,
                           const std::string &fn_name) {
  if (pid_stat_ && pid_stat_->is_stale())
    return false;

  // FIXME: we may have issues here if the context has two same probes's
  // but different providers. For example, libc:setjmp and rtld:setjmp,
  // libc:lll_futex_wait and rtld:lll_futex_wait.
  Probe *found_probe = nullptr;
  for (auto &p : probes_) {
    if (p->name_ == probe_name) {
      if (found_probe != nullptr) {
         fprintf(stderr, "Two same-name probes (%s) but different providers\n",
                 probe_name.c_str());
         return false;
      }
      found_probe = p.get();
    }
  }

  if (found_probe != nullptr) {
    found_probe->enable(fn_name);
    return true;
  }

  return false;
}

void Context::each(each_cb callback) {
  for (const auto &probe : probes_) {
    struct bcc_usdt info = {0};
    info.provider = probe->provider().c_str();
    info.bin_path = probe->bin_path().c_str();
    info.name = probe->name().c_str();
    info.semaphore = probe->semaphore();
    info.num_locations = probe->num_locations();
    info.num_arguments = probe->num_arguments();
    callback(&info);
  }
}

void Context::each_uprobe(each_uprobe_cb callback) {
  for (auto &p : probes_) {
    if (!p->enabled())
      continue;

    for (Location &loc : p->locations_) {
      callback(loc.bin_path_.c_str(), p->attached_to_->c_str(), loc.address_,
               pid_.value_or(-1));
    }
  }
}

Context::Context(const std::string &bin_path)
    : mount_ns_instance_(new ProcMountNS(-1)), loaded_(false) {
  std::string full_path = resolve_bin_path(bin_path);
  if (!full_path.empty()) {
    if (bcc_elf_foreach_usdt(full_path.c_str(), _each_probe, this) == 0) {
      cmd_bin_path_ = full_path;
      loaded_ = true;
    }
  }
  for (const auto &probe : probes_)
    probe->finalize_locations();
}

Context::Context(int pid) : pid_(pid), pid_stat_(pid),
  mount_ns_instance_(new ProcMountNS(pid)), loaded_(false) {
  if (bcc_procutils_each_module(pid, _each_module, this) == 0) {
    cmd_bin_path_ = ebpf::get_pid_exe(pid);
    if (cmd_bin_path_.empty())
      return;

    loaded_ = true;
  }
  for (const auto &probe : probes_)
    probe->finalize_locations();
}

Context::Context(int pid, const std::string &bin_path)
    : pid_(pid), pid_stat_(pid),
      mount_ns_instance_(new ProcMountNS(pid)), loaded_(false) {
  std::string full_path = resolve_bin_path(bin_path);
  if (!full_path.empty()) {
    if (bcc_elf_foreach_usdt(full_path.c_str(), _each_probe, this) == 0) {
      cmd_bin_path_ = ebpf::get_pid_exe(pid);
      if (cmd_bin_path_.empty())
        return;
      loaded_ = true;
    }
  }
  for (const auto &probe : probes_)
    probe->finalize_locations();
}

Context::~Context() {
  if (pid_stat_ && !pid_stat_->is_stale()) {
    for (auto &p : probes_) p->disable();
  }
}
}

extern "C" {

void *bcc_usdt_new_frompid(int pid, const char *path) {
  USDT::Context *ctx;

  if (!path) {
    ctx = new USDT::Context(pid);
  } else {
    struct stat buffer;
    if (strlen(path) >= 1 && path[0] != '/') {
      fprintf(stderr, "HINT: Binary path should be absolute.\n\n");
      return nullptr;
    } else if (stat(path, &buffer) == -1) {
      fprintf(stderr, "HINT: Specified binary doesn't exist.\n\n");
      return nullptr;
    }
    ctx = new USDT::Context(pid, path);
  }
  if (!ctx->loaded()) {
    delete ctx;
    return nullptr;
  }
  return static_cast<void *>(ctx);
}

void *bcc_usdt_new_frompath(const char *path) {
  USDT::Context *ctx = new USDT::Context(path);
  if (!ctx->loaded()) {
    delete ctx;
    return nullptr;
  }
  return static_cast<void *>(ctx);
}

void bcc_usdt_close(void *usdt) {
  if (usdt) {
    USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
    delete ctx;
  }
}

int bcc_usdt_enable_probe(void *usdt, const char *probe_name,
                          const char *fn_name) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  return ctx->enable_probe(probe_name, fn_name) ? 0 : -1;
}

const char *bcc_usdt_genargs(void **usdt_array, int len) {
  static std::string storage_;
  std::ostringstream stream;

  if (!len)
    return "";

  stream << USDT::USDT_PROGRAM_HEADER;
  // Generate genargs codes for an array of USDT Contexts.
  //
  // Each mnt_point + cmd_bin_path + probe_provider + probe_name
  // uniquely identifies a probe.
  std::unordered_set<std::string> generated_probes;
  for (int i = 0; i < len; i++) {
    USDT::Context *ctx = static_cast<USDT::Context *>(usdt_array[i]);

    for (size_t j = 0; j < ctx->num_probes(); j++) {
      USDT::Probe *p = ctx->get(j);
      if (p->enabled()) {
        std::string key = std::to_string(ctx->inode()) + "*"
          + ctx->cmd_bin_path() + "*" + p->provider() + "*" + p->name();
        if (generated_probes.find(key) != generated_probes.end())
          continue;
        if (!p->usdt_getarg(stream))
          return nullptr;
        generated_probes.insert(key);
      }
    }
  }

  storage_ = stream.str();
  return storage_.c_str();
}

const char *bcc_usdt_get_probe_argctype(
  void *ctx, const char* probe_name, const int arg_index
) {
  USDT::Probe *p = static_cast<USDT::Context *>(ctx)->get(probe_name);
  std::string res = p ? p->get_arg_ctype(arg_index) : "";
  return res.c_str();
}

void bcc_usdt_foreach(void *usdt, bcc_usdt_cb callback) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  ctx->each(callback);
}

int bcc_usdt_get_location(void *usdt, const char *provider_name,
                          const char *probe_name,
                          int index, struct bcc_usdt_location *location) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  USDT::Probe *probe = ctx->get(provider_name, probe_name);
  if (!probe)
    return -1;
  if (index < 0 || (size_t)index >= probe->num_locations())
    return -1;
  location->address = probe->address(index);
  location->bin_path = probe->location_bin_path(index);
  return 0;
}

int bcc_usdt_get_argument(void *usdt, const char *provider_name,
                          const char *probe_name,
                          int location_index, int argument_index,
                          struct bcc_usdt_argument *argument) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  USDT::Probe *probe = ctx->get(provider_name, probe_name);
  if (!probe)
    return -1;
  if (argument_index < 0 || (size_t)argument_index >= probe->num_arguments())
    return -1;
  if (location_index < 0 || (size_t)location_index >= probe->num_locations())
    return -1;
  auto const &location = probe->location(location_index);
  auto const &arg = location.arguments_[argument_index];
  argument->size = arg.arg_size();
  argument->valid = BCC_USDT_ARGUMENT_NONE;
  if (arg.constant()) {
    argument->valid |= BCC_USDT_ARGUMENT_CONSTANT;
    argument->constant = *(arg.constant());
  }
  if (arg.deref_offset()) {
    argument->valid |= BCC_USDT_ARGUMENT_DEREF_OFFSET;
    argument->deref_offset = *(arg.deref_offset());
  }
  if (arg.deref_ident()) {
    argument->valid |= BCC_USDT_ARGUMENT_DEREF_IDENT;
    argument->deref_ident = arg.deref_ident()->c_str();
  }
  if (arg.base_register_name()) {
    argument->valid |= BCC_USDT_ARGUMENT_BASE_REGISTER_NAME;
    argument->base_register_name = arg.base_register_name()->c_str();
  }
  if (arg.index_register_name()) {
    argument->valid |= BCC_USDT_ARGUMENT_INDEX_REGISTER_NAME;
    argument->index_register_name = arg.index_register_name()->c_str();
  }
  if (arg.scale()) {
    argument->valid |= BCC_USDT_ARGUMENT_SCALE;
    argument->scale = *(arg.scale());
  }
  return 0;
}

void bcc_usdt_foreach_uprobe(void *usdt, bcc_usdt_uprobe_cb callback) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  ctx->each_uprobe(callback);
}
}
