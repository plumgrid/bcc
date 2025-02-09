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

#include "bcc_syms.h"

#include <cxxabi.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/elf.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

#include "bcc_elf.h"
#include "bcc_perf_map.h"
#include "bcc_proc.h"
#include "common.h"
#include "syms.h"
#include "vendor/tinyformat.hpp"

ProcSyms::ModulePath::ModulePath(const std::string &ns_path, int root_fd,
                                 int pid, bool enter_ns) {
  if (!enter_ns) {
    path_ = ns_path;
    proc_root_path_ = ns_path;
    return;
  }
  proc_root_path_ = tfm::format("/proc/%d/root%s", pid, ns_path);
  // filename for openat must not contain any starting slashes, otherwise
  // it would get treated as an absolute path
  std::string trimmed_path;
  size_t non_slash_pos;
  for (non_slash_pos = 0;
       non_slash_pos < ns_path.size() && ns_path[non_slash_pos] == '/';
       non_slash_pos++)
    ;
  trimmed_path = ns_path.substr(non_slash_pos);
  fd_ = openat(root_fd, trimmed_path.c_str(), O_RDONLY);
  if (fd_ > 0)
    path_ = tfm::format("/proc/self/fd/%d", fd_);
  else
    // openat failed, fall back to /proc/.../root path
    path_ = proc_root_path_;
}

bool ProcStat::getinode_(ino_t &inode) {
  struct stat s;
  if (!stat(procfs_.c_str(), &s)) {
    inode = s.st_ino;
    return true;
  } else {
    return false;
  }
}

bool ProcStat::refresh_root() {
  // try to current root and mount namespace for process
  char current_root[PATH_MAX], current_mount_ns[PATH_MAX];
  if (readlink(root_symlink_.c_str(), current_root, PATH_MAX) < 0 ||
      readlink(mount_ns_symlink_.c_str(), current_mount_ns, PATH_MAX) < 0)
    // readlink failed, process might not exist anymore; keep old fd
    return false;

  // check if root fd is up to date
  if (root_fd_ != -1 && current_root == root_ && current_mount_ns == mount_ns_)
    return false;

  root_ = current_root;
  mount_ns_ = current_mount_ns;

  // either root fd is invalid or process root and/or mount namespace changed;
  // re-open root note: when /proc/.../root changes, the open file descriptor
  // still refers to the old one
  int original_root_fd = root_fd_;
  root_fd_ = open(root_symlink_.c_str(), O_PATH);
  if (root_fd_ == -1)
    std::cerr << "Opening " << root_symlink_ << " failed: " << strerror(errno)
              << std::endl;
  if (original_root_fd > 0)
    close(original_root_fd);
  return original_root_fd != root_fd_;
}

bool ProcStat::is_stale() {
  ino_t cur_inode;
  return getinode_(cur_inode) && (cur_inode != inode_) && refresh_root();
}

ProcStat::ProcStat(int pid)
    : procfs_(tfm::format("/proc/%d/exe", pid)),
      root_symlink_(tfm::format("/proc/%d/root", pid)),
      mount_ns_symlink_(tfm::format("/proc/%d/ns/mnt", pid)) {
  getinode_(inode_);
  refresh_root();
}

void KSyms::_add_symbol(const char *symname, const char *modname, uint64_t addr, void *p) {
  KSyms *ks = static_cast<KSyms *>(p);
  ks->syms_.emplace_back(symname, modname, addr);
}

void KSyms::refresh() {
  if (syms_.empty()) {
    bcc_procutils_each_ksym(_add_symbol, this);
    std::sort(syms_.begin(), syms_.end());
  }
}

bool KSyms::resolve_addr(uint64_t addr, struct bcc_symbol *sym, bool demangle) {
  refresh();

  std::vector<Symbol>::iterator it;

  if (syms_.empty())
    goto unknown_symbol;

  it = std::upper_bound(syms_.begin(), syms_.end(), Symbol("", "", addr));
  if (it != syms_.begin()) {
    it--;
    sym->name = (*it).name.c_str();
    if (demangle)
      sym->demangle_name = sym->name;
    sym->module = (*it).mod.c_str();
    sym->offset = addr - (*it).addr;
    return true;
  }

unknown_symbol:
  memset(sym, 0, sizeof(struct bcc_symbol));
  return false;
}

bool KSyms::resolve_name(const char *_unused, const char *name,
                         uint64_t *addr) {
  refresh();

  if (syms_.size() != symnames_.size()) {
    symnames_.clear();
    for (Symbol &sym : syms_) {
      symnames_[sym.name] = sym.addr;
    }
  }

  auto it = symnames_.find(name);
  if (it == symnames_.end())
    return false;

  *addr = it->second;
  return true;
}

ProcSyms::ProcSyms(int pid, struct bcc_symbol_option *option)
    : pid_(pid), procstat_(pid) {
  if (option)
    std::memcpy(&symbol_option_, option, sizeof(bcc_symbol_option));
  else
    symbol_option_ = {
      .use_debug_file = 1,
      .check_debug_file_crc = 1,
      .lazy_symbolize = 1,
      .use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC)
    };
  load_modules();
}

void ProcSyms::load_modules() {
  bcc_procutils_each_module(pid_, _add_module, this);
}

void ProcSyms::refresh() {
  modules_.clear();
  load_modules();
  procstat_.reset();
}

int ProcSyms::_add_module(mod_info *mod, int enter_ns, void *payload) {
  ProcSyms *ps = static_cast<ProcSyms *>(payload);
  std::shared_ptr<ModulePath> modpath =
      std::make_shared<ModulePath>(mod->name, ps->procstat_.get_root_fd(),
                                   ps->pid_, enter_ns && ps->pid_ != -1);
  auto it = std::find_if(
      ps->modules_.begin(), ps->modules_.end(),
      [=](const ProcSyms::Module &m) { return m.name_ == mod->name; });
  if (it == ps->modules_.end()) {
    auto module = Module(
        mod->name, modpath, &ps->symbol_option_);

    // pid/maps doesn't account for file_offset of text within the ELF.
    // It only gives the mmap offset. We need the real offset for symbol
    // lookup.
    if (module.type_ == ModuleType::SO) {
      if (bcc_elf_get_text_scn_info(modpath->path(), &module.elf_so_addr_,
                                    &module.elf_so_offset_) < 0) {
        fprintf(stderr, "WARNING: Couldn't find .text section in %s\n",
                modpath->alt_path());
        fprintf(stderr, "WARNING: BCC can't handle sym look ups for %s",
                modpath->alt_path());
      }
    }

    if (!bcc_is_perf_map(modpath->path()) ||
        module.type_ != ModuleType::UNKNOWN)
      // Always add the module even if we can't read it, so that we could
      // report correct module name. Unless it's a perf map that we only
      // add readable ones.
      it = ps->modules_.insert(ps->modules_.end(), std::move(module));
    else
      return 0;
  }
  it->ranges_.emplace_back(mod->start_addr, mod->end_addr, mod->file_offset);
  // perf-PID map is added last. We try both inside the Process's mount
  // namespace + chroot, and in global /tmp. Make sure we only add one.
  if (it->type_ == ModuleType::PERF_MAP)
    return -1;

  return 0;
}

bool ProcSyms::resolve_addr(uint64_t addr, struct bcc_symbol *sym,
                            bool demangle) {
  if (procstat_.is_stale())
    refresh();

  memset(sym, 0, sizeof(struct bcc_symbol));

  const char *original_module = nullptr;
  uint64_t offset;
  bool only_perf_map = false;
  for (Module &mod : modules_) {
    if (only_perf_map && (mod.type_ != ModuleType::PERF_MAP))
      continue;
    if (mod.contains(addr, offset)) {
      if (mod.find_addr(offset, sym)) {
        if (demangle) {
          if (sym->name && (!strncmp(sym->name, "_Z", 2) || !strncmp(sym->name, "___Z", 4)))
            sym->demangle_name =
                abi::__cxa_demangle(sym->name, nullptr, nullptr, nullptr);
          if (!sym->demangle_name)
            sym->demangle_name = sym->name;
        }
        return true;
      } else if (mod.type_ != ModuleType::PERF_MAP) {
        // In this case, we found the address in the range of a module, but
        // not able to find a symbol of that address in the module.
        // Thus, we would try to find the address in perf map, and
        // save the module's name in case we will need it later.
        original_module = mod.name_.c_str();
        only_perf_map = true;
      }
    }
  }
  // If we didn't find the symbol anywhere, the module name is probably
  // set to be the perf map's name as it would be the last we tried.
  // In this case, if we have found the address previously in a module,
  // report the saved original module name instead.
  if (original_module)
    sym->module = original_module;
  return false;
}

bool ProcSyms::resolve_name(const char *module, const char *name,
                            uint64_t *addr) {
  if (procstat_.is_stale())
    refresh();

  for (Module &mod : modules_) {
    if (mod.name_ == module)
      return mod.find_name(name, addr);
  }
  return false;
}

ProcSyms::Module::Module(const char *name, std::shared_ptr<ModulePath> path,
                         struct bcc_symbol_option *option)
    : name_(name),
      path_(path),
      loaded_(false),
      symbol_option_(option),
      type_(ModuleType::UNKNOWN) {
  int elf_type = bcc_elf_get_type(path_->path());
  // The Module is an ELF file
  if (elf_type >= 0) {
    if (elf_type == ET_EXEC)
      type_ = ModuleType::EXEC;
    else if (elf_type == ET_DYN)
      type_ = ModuleType::SO;
    return;
  }
  // Other symbol files
  if (bcc_is_valid_perf_map(path_->path()) == 1)
    type_ = ModuleType::PERF_MAP;
  else if (bcc_elf_is_vdso(path_->path()) == 1)
    type_ = ModuleType::VDSO;

  // Will be stored later
  elf_so_offset_ = 0;
  elf_so_addr_ = 0;
}

int ProcSyms::Module::_add_symbol(const char *symname, uint64_t start,
                                  uint64_t size, void *p) {
  Module *m = static_cast<Module *>(p);
  auto res = m->symnames_.emplace(symname);
  m->syms_.emplace_back(&*(res.first), start, size);
  return 0;
}

int ProcSyms::Module::_add_symbol_lazy(size_t section_idx, size_t str_table_idx,
                                       size_t str_len, uint64_t start,
                                       uint64_t size, int debugfile, void *p) {
  Module *m = static_cast<Module *>(p);
  m->syms_.emplace_back(
      section_idx, str_table_idx, str_len, start, size, debugfile);
  return 0;
}

void ProcSyms::Module::load_sym_table() {
  if (loaded_)
    return;
  loaded_ = true;

  if (type_ == ModuleType::UNKNOWN)
    return;

  if (type_ == ModuleType::PERF_MAP)
    bcc_perf_map_foreach_sym(path_->path(), _add_symbol, this);
  if (type_ == ModuleType::EXEC || type_ == ModuleType::SO) {
    if (symbol_option_->lazy_symbolize)
      bcc_elf_foreach_sym_lazy(path_->path(), _add_symbol_lazy, symbol_option_,
                               this);
    else
      bcc_elf_foreach_sym(path_->path(), _add_symbol, symbol_option_, this);
  }
  if (type_ == ModuleType::VDSO)
    bcc_elf_foreach_vdso_sym(_add_symbol, this);

  std::sort(syms_.begin(), syms_.end());
}

bool ProcSyms::Module::contains(uint64_t addr, uint64_t &offset) const {
  for (const auto &range : ranges_) {
    if (addr >= range.start && addr < range.end) {
      if (type_ == ModuleType::SO || type_ == ModuleType::VDSO) {
        offset = __so_calc_mod_offset(range.start, range.file_offset,
                                      elf_so_addr_, elf_so_offset_, addr);
      } else {
        offset = addr;
      }

      return true;
    }
  }

  return false;
}

bool ProcSyms::Module::find_name(const char *symname, uint64_t *addr) {
  struct Payload {
    const char *symname;
    uint64_t *out;
    bool found;
  };

  Payload payload;
  payload.symname = symname;
  payload.out = addr;
  payload.found = false;

  auto cb = [](const char *name, uint64_t start, uint64_t size, void *p) {
    Payload *payload = static_cast<Payload*>(p);

    if (!strcmp(payload->symname, name)) {
      payload->found = true;
      *(payload->out) = start;
      return -1;  // Stop iteration
    }

    return 0;
  };

  if (type_ == ModuleType::PERF_MAP)
    bcc_perf_map_foreach_sym(path_->path(), cb, &payload);
  if (type_ == ModuleType::EXEC || type_ == ModuleType::SO) {
    bcc_elf_foreach_sym(path_->path(), cb, symbol_option_, &payload);
    if (path_->path() != path_->alt_path())
      // some features (e.g. some kinds of debug info) don't work with /proc/self/fd/... path
      bcc_elf_foreach_sym(path_->alt_path(), cb, symbol_option_, &payload);
  }
  if (type_ == ModuleType::VDSO)
    bcc_elf_foreach_vdso_sym(cb, &payload);

  if (!payload.found)
    return false;

  if (type_ == ModuleType::SO)
    *(payload.out) += start();

  return true;
}

bool ProcSyms::Module::find_addr(uint64_t offset, struct bcc_symbol *sym) {
  load_sym_table();

  sym->module = name_.c_str();
  sym->offset = offset;

  auto it = std::upper_bound(syms_.begin(), syms_.end(), Symbol(nullptr, offset, 0));
  if (it == syms_.begin())
    return false;

  // 'it' points to the symbol whose start address is strictly greater than
  // the address we're looking for. Start stepping backwards as long as the
  // current symbol is still below the desired address, and see if the end
  // of the current symbol (start + size) is above the desired address. Once
  // we have a matching symbol, return it. Note that simply looking at '--it'
  // is not enough, because symbols can be nested. For example, we could be
  // looking for offset 0x12 with the following symbols available:
  // SYMBOL   START   SIZE    END
  // goo      0x0     0x6     0x0 + 0x6 = 0x6
  // foo      0x6     0x10    0x6 + 0x10 = 0x16
  // bar      0x8     0x4     0x8 + 0x4 = 0xc
  // baz      0x16    0x10    0x16 + 0x10 = 0x26
  // The upper_bound lookup will return baz, and then going one symbol back
  // brings us to bar, which does not contain offset 0x12 and is nested inside
  // foo. Going back one more symbol brings us to foo, which contains 0x12
  // and is a match.
  // However, we also don't want to walk through the entire symbol list for
  // unknown / missing symbols. So we will break if we reach a function that
  // doesn't cover the function immediately before 'it', which means it is
  // not possibly a nested function containing the address we're looking for.
  --it;
  uint64_t limit = it->start;
  for (; offset >= it->start; --it) {
    if (offset < it->start + it->size) {
      // Resolve and cache the symbol name if necessary
      if (!it->is_name_resolved) {
        std::string sym_name(it->data.name_idx.str_len + 1, '\0');
        if (bcc_elf_symbol_str(path_->path(), it->data.name_idx.section_idx,
                               it->data.name_idx.str_table_idx, &sym_name[0],
                               sym_name.size(), it->data.name_idx.debugfile))
          break;

        it->data.name = &*(symnames_.emplace(std::move(sym_name)).first);
        it->is_name_resolved = true;
      }

      sym->name = it->data.name->c_str();
      sym->offset = (offset - it->start);
      return true;
    }
    if (limit > it->start + it->size)
      break;
    // But don't step beyond begin()!
    if (it == syms_.begin())
      break;
  }

  return false;
}

bool BuildSyms::Module::load_sym_table()
{
  if (loaded_)
    return true;

  symbol_option_ = {
    .use_debug_file = 1,
    .check_debug_file_crc = 1,
    .lazy_symbolize = 1,
    .use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC)
  };

  bcc_elf_foreach_sym(module_name_.c_str(), _add_symbol, &symbol_option_, this);
  std::sort(syms_.begin(), syms_.end());

  for(std::vector<Symbol>::iterator it = syms_.begin();
      it != syms_.end(); ++it++) {
  }
  loaded_ = true;
  return true;
}

int BuildSyms::Module::_add_symbol(const char *symname, uint64_t start,
                                   uint64_t size, void *p)
{
  BuildSyms::Module *m = static_cast<BuildSyms::Module *> (p);
  auto res = m->symnames_.emplace(symname);
  m->syms_.emplace_back(&*(res.first), start, size);
  return 0;
}

bool BuildSyms::Module::resolve_addr(uint64_t offset, struct bcc_symbol* sym,
                                     bool demangle)
{
  std::vector<Symbol>::iterator it;

  load_sym_table();

  if (syms_.empty())
    goto unknown_symbol;

  it = std::upper_bound(syms_.begin(), syms_.end(), Symbol(nullptr, offset, 0));
  if (it != syms_.begin()) {
    it--;
    sym->name = (*it).name->c_str();
    if (demangle)
      sym->demangle_name = sym->name;
    sym->offset = offset - (*it).start;
    sym->module = module_name_.c_str();
    return true;
  }

unknown_symbol:
  memset(sym, 0, sizeof(struct bcc_symbol));
  return false;
}

bool BuildSyms::add_module(const std::string module_name)
{
  struct stat s;
  char buildid[BPF_BUILD_ID_SIZE*2+1];

  if (stat(module_name.c_str(), &s) < 0)
     return false;

  if (bcc_elf_get_buildid(module_name.c_str(), buildid) < 0)
      return false;

  std::string elf_buildid(buildid);
  std::unique_ptr<BuildSyms::Module> ptr(new BuildSyms::Module(module_name.c_str()));
  buildmap_[elf_buildid] = std::move(ptr);
  return true;
}

bool BuildSyms::resolve_addr(std::string build_id, uint64_t offset,
                             struct bcc_symbol *sym, bool demangle)
{
  std::unordered_map<std::string,std::unique_ptr<BuildSyms::Module> >::iterator it;

  it = buildmap_.find(build_id);
  if (it == buildmap_.end())
    /*build-id not added to the BuildSym*/
    return false;

  BuildSyms::Module *mod = it->second.get();
  return mod->resolve_addr(offset, sym, demangle);
}

extern "C" {

void *bcc_symcache_new(int pid, struct bcc_symbol_option *option) {
  if (pid < 0)
    return static_cast<void *>(new KSyms());
  return static_cast<void *>(new ProcSyms(pid, option));
}

void bcc_free_symcache(void *symcache, int pid) {
  if (pid < 0)
    delete static_cast<KSyms*>(symcache);
  else
    delete static_cast<ProcSyms*>(symcache);
}

void bcc_symbol_free_demangle_name(struct bcc_symbol *sym) {
  if (sym->demangle_name && (sym->demangle_name != sym->name))
    free(const_cast<char*>(sym->demangle_name));
}

int bcc_symcache_resolve(void *resolver, uint64_t addr,
                         struct bcc_symbol *sym) {
  SymbolCache *cache = static_cast<SymbolCache *>(resolver);
  return cache->resolve_addr(addr, sym) ? 0 : -1;
}

int bcc_symcache_resolve_no_demangle(void *resolver, uint64_t addr,
                                     struct bcc_symbol *sym) {
  SymbolCache *cache = static_cast<SymbolCache *>(resolver);
  return cache->resolve_addr(addr, sym, false) ? 0 : -1;
}

int bcc_symcache_resolve_name(void *resolver, const char *module,
                              const char *name, uint64_t *addr) {
  SymbolCache *cache = static_cast<SymbolCache *>(resolver);
  return cache->resolve_name(module, name, addr) ? 0 : -1;
}

void bcc_symcache_refresh(void *resolver) {
  SymbolCache *cache = static_cast<SymbolCache *>(resolver);
  cache->refresh();
}

void *bcc_buildsymcache_new(void) {
  return static_cast<void *>(new BuildSyms());
}

void bcc_free_buildsymcache(void *symcache) {
  delete static_cast<BuildSyms*>(symcache);
}

int  bcc_buildsymcache_add_module(void *resolver, const char *module_name)
{
  BuildSyms *bsym = static_cast<BuildSyms *>(resolver);
  return  bsym->add_module(module_name) ? 0 : -1;
}

int bcc_buildsymcache_resolve(void *resolver,
                              struct bpf_stack_build_id *trace,
                              struct bcc_symbol *sym)
{
  std::string build_id;
  unsigned char *c = &trace->build_id[0];
  int idx = 0;

  /*cannot resolve in case of fallback*/
  if (trace->status == BPF_STACK_BUILD_ID_EMPTY ||
      trace->status == BPF_STACK_BUILD_ID_IP)
    return 0;

  while( idx < 20) {
    int nib1 = (c[idx]&0xf0)>>4;
    int nib2 = (c[idx]&0x0f);
    build_id += "0123456789abcdef"[nib1];
    build_id += "0123456789abcdef"[nib2];
    idx++;
  }

  BuildSyms *bsym = static_cast<BuildSyms *>(resolver);
  return bsym->resolve_addr(build_id, trace->offset, sym) ? 0 : -1;
}

struct mod_search {
  const char *name;
  uint64_t inode;
  uint64_t dev_major;
  uint64_t dev_minor;
  uint64_t addr;
  uint8_t inode_match_only;

  uint64_t start;
  uint64_t file_offset;
};

int _bcc_syms_find_module(mod_info *info, int enter_ns, void *p) {
  struct mod_search *mod = (struct mod_search *)p;
  // use inode + dev to determine match if inode set
  if (mod->inode) {
    if (mod->inode != info->inode)
      return 0;

    // look at comment on USDT::set_probe_matching_kludge
    // in api/BPF.h for explanation of why this might be
    // necessary
    if (mod->inode_match_only)
      goto file_match;

    if(mod->dev_major == info->dev_major
        && mod->dev_minor == info->dev_minor)
      goto file_match;

    return 0;
  }

  // fallback to name match
  if (!strcmp(info->name, mod->name))
    goto file_match;

  return 0;

file_match:
  mod->start = info->start_addr;
  mod->file_offset = info->file_offset;
  return -1;
}

uint64_t __so_calc_global_addr(uint64_t mod_start_addr,
                               uint64_t mod_file_offset,
                               uint64_t elf_sec_start_addr,
                               uint64_t elf_sec_file_offset, uint64_t offset) {
  return offset + (mod_start_addr - mod_file_offset) -
         (elf_sec_start_addr - elf_sec_file_offset);
}

uint64_t __so_calc_mod_offset(uint64_t mod_start_addr, uint64_t mod_file_offset,
                              uint64_t elf_sec_start_addr,
                              uint64_t elf_sec_file_offset,
                              uint64_t global_addr) {
  return global_addr - (mod_start_addr - mod_file_offset) +
         (elf_sec_start_addr - elf_sec_file_offset);
}

int bcc_resolve_global_addr(int pid, const char *module, const uint64_t address,
                            uint8_t inode_match_only, uint64_t *global) {
  struct stat s;
  uint64_t elf_so_addr, elf_so_offset;
  if (stat(module, &s))
    return -1;

  struct mod_search mod = {module, s.st_ino, major(s.st_dev), minor(s.st_dev),
                           address, inode_match_only,
                           0x0, 0x0};
  if (bcc_procutils_each_module(pid, _bcc_syms_find_module, &mod) < 0 ||
      mod.start == 0x0)
    return -1;

  if (bcc_elf_get_text_scn_info(module, &elf_so_addr, &elf_so_offset) < 0)
    return -1;

  *global = __so_calc_global_addr(mod.start, mod.file_offset, elf_so_addr,
                                  elf_so_offset, address);
  return 0;
}

static int _sym_cb_wrapper(const char *symname, uint64_t addr, uint64_t,
                           void *payload) {
  SYM_CB cb = (SYM_CB) payload;
  return cb(symname, addr);
}

int bcc_foreach_function_symbol(const char *module, SYM_CB cb) {
  if (module == 0 || cb == 0)
    return -1;

  static struct bcc_symbol_option default_option = {
    .use_debug_file = 1,
    .check_debug_file_crc = 1,
    .lazy_symbolize = 1,
    .use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC)
  };

  return bcc_elf_foreach_sym(
      module, _sym_cb_wrapper, &default_option, (void *)cb);
}

static int _find_sym(const char *symname, uint64_t addr, uint64_t,
                     void *payload) {
  struct bcc_symbol *sym = (struct bcc_symbol *)payload;
  if (!strcmp(sym->name, symname)) {
    sym->offset = addr - sym->base_address;
    return -1;
  }
  return 0;
}

static int _get_base_address(uint64_t v_addr, uint64_t mem_sz, uint64_t file_offset,
                       void *payload) {
  struct bcc_symbol *sym = (struct bcc_symbol *)payload;
  if ( v_addr >= file_offset) {
    sym->base_address = v_addr - file_offset;
    return -1;
  }
  return 0;
}

struct load_addr_t {
  uint64_t target_addr;
  uint64_t binary_addr;
};
int _find_load(uint64_t v_addr, uint64_t mem_sz, uint64_t file_offset,
                       void *payload) {
  struct load_addr_t *addr = static_cast<load_addr_t *>(payload);
  if (addr->target_addr >= v_addr && addr->target_addr < (v_addr + mem_sz)) {
    addr->binary_addr = addr->target_addr - v_addr + file_offset;
    return -1;
  }
  return 0;
}

int bcc_resolve_symname(const char *module, const char *symname,
                        const uint64_t addr, int pid,
                        struct bcc_symbol_option *option,
                        struct bcc_symbol *sym) {
  int module_type;
  static struct bcc_symbol_option default_option = {
    .use_debug_file = 1,
    .check_debug_file_crc = 1,
    .lazy_symbolize = 1,
#if defined(__powerpc64__) && defined(_CALL_ELF) && _CALL_ELF == 2
    .use_symbol_type = BCC_SYM_ALL_TYPES | (1 << STT_PPC64_ELFV2_SYM_LEP),
#else
    .use_symbol_type = BCC_SYM_ALL_TYPES,
#endif
  };
  int update_flag = 0;

  if (module == NULL)
    return -1;

  memset(sym, 0, sizeof(bcc_symbol));

  if (strchr(module, '/')) {
    sym->module = strdup(module);
  } else {
    sym->module = bcc_procutils_which_so(module, pid);
  }
  if (sym->module == NULL)
    return -1;
  if (pid != 0 && pid != -1 && strstr(sym->module, "/proc") != sym->module){
    char *temp = (char*)sym->module;
    sym->module = strdup(tfm::format("/proc/%d/root%s", pid, sym->module).c_str());
    free(temp);
  }

  sym->name = symname;
  sym->offset = addr;
  if (bcc_elf_foreach_load_section(sym->module, _get_base_address, sym) < 0)
      goto invalid_module;
  if (option == NULL)
    option = &default_option;

  if (sym->name && sym->offset == 0x0){
    if (bcc_elf_foreach_sym(sym->module, _find_sym, option, sym) < 0)
      goto invalid_module;
    update_flag = 1;
  }
  if (sym->offset == 0x0)
    goto invalid_module;

  // For executable (ET_EXEC) binaries and shared objects (ET_DYN), translate
  // the virtual address to physical address in the binary file.
  module_type = bcc_elf_get_type(sym->module);
  if (module_type == ET_EXEC || module_type == ET_DYN) {
    struct load_addr_t addr = {
      .target_addr = sym->offset,
      .binary_addr = 0x0,
    };
    if(update_flag)
      addr.target_addr += sym->base_address;
    if (bcc_elf_foreach_load_section(sym->module, &_find_load, &addr) < 0)
      goto invalid_module;
    if (!addr.binary_addr)
      goto invalid_module;
    sym->offset = addr.binary_addr;
  }
  return 0;

invalid_module:
  if (sym->module) {
    ::free(const_cast<char*>(sym->module));
    sym->module = NULL;
  }
  return -1;
}
}
