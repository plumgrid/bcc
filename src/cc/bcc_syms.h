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
#ifndef LIBBCC_SYMS_H
#define LIBBCC_SYMS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "linux/bpf.h"
#include "bcc_proc.h"

struct bcc_symbol {
  const char *name;
  const char *demangle_name;
  const char *module;
  uint64_t offset;
  uint64_t base_address;
};

typedef int (*SYM_CB)(const char *symname, uint64_t addr);
struct mod_info;

#ifndef STT_GNU_IFUNC
#define STT_GNU_IFUNC 10
#endif

#if defined(__powerpc64__) && defined(_CALL_ELF) && _CALL_ELF == 2
// Indicate if the Local Entry Point (LEP) should be used as a symbol's
// start address
#define STT_PPC64_ELFV2_SYM_LEP 31
#endif

static const uint32_t BCC_SYM_ALL_TYPES = 65535;
struct bcc_symbol_option {
  int use_debug_file;
  int check_debug_file_crc;
  // Symbolize on-demand or symbolize everything ahead of time
  int lazy_symbolize;
  // Bitmask flags indicating what types of ELF symbols to use
  uint32_t use_symbol_type;
};

void *bcc_symcache_new(int pid, struct bcc_symbol_option *option);
void bcc_free_symcache(void *symcache, int pid);

// The demangle_name pointer in bcc_symbol struct is returned from the
// __cxa_demangle function call, which is supposed to be freed by caller. Call
// this function after done using returned result of bcc_symcache_resolve.
void bcc_symbol_free_demangle_name(struct bcc_symbol *sym);
int bcc_symcache_resolve(void *symcache, uint64_t addr, struct bcc_symbol *sym);
int bcc_symcache_resolve_no_demangle(void *symcache, uint64_t addr,
                                     struct bcc_symbol *sym);

int bcc_symcache_resolve_name(void *resolver, const char *module,
                              const char *name, uint64_t *addr);
void bcc_symcache_refresh(void *resolver);

int _bcc_syms_find_module(struct mod_info *info, int enter_ns, void *p);
int bcc_resolve_global_addr(int pid, const char *module, const uint64_t address,
                            uint8_t inode_match_only, uint64_t *global);

/*bcc APIs for build_id stackmap support*/
void *bcc_buildsymcache_new(void);
void bcc_free_buildsymcache(void *symcache);
int  bcc_buildsymcache_add_module(void *resolver, const char *module_name);
int bcc_buildsymcache_resolve(void *resolver,
                              struct bpf_stack_build_id *trace,
                              struct bcc_symbol *sym);
// Call cb on every function symbol in the specified module. Uses simpler
// SYM_CB callback mainly for easier to use in Python API.
// Will prefer use debug file and check debug file CRC when reading the module.
int bcc_foreach_function_symbol(const char *module, SYM_CB cb);

// Find the offset of a symbol in a module binary. If addr is not zero, will
// calculate the offset using the provided addr and the module's load address.
//
// If pid is provided, will use it to help lookup the module in the Process and
// enter the Process's mount Namespace.
//
// If option is not NULL, will respect the specified options for lookup.
// Otherwise default option will apply, which is to use debug file, verify
// checksum, and try all types of symbols.
//
// Return 0 on success and -1 on failure. Output will be write to sym. After
// use, sym->module need to be freed if it's not empty.
int bcc_resolve_symname(const char *module, const char *symname,
                        const uint64_t addr, int pid,
                        struct bcc_symbol_option* option,
                        struct bcc_symbol *sym);

/* Calculate the global address for 'offset' in a shared object loaded into
 * a process
 *
 * Need to know (start_addr, file_offset) pairs for the /proc/PID/maps module
 * entry containing the offset and the elf section containing the module's
 * .text
 */
uint64_t __so_calc_global_addr(uint64_t mod_start_addr,
                               uint64_t mod_file_offset,
                               uint64_t elf_sec_start_addr,
                               uint64_t elf_sec_file_offset, uint64_t offset);

/* Given a global address which falls within a shared object's mapping in a
 * process, calculate the corresponding 'offset' in the .so
 *
 * Need to know (start_addr, file_offset) pairs for the /proc/PID/maps module
 * entry containing the offset and the elf section containing the module's
 * .text
 */
uint64_t __so_calc_mod_offset(uint64_t mod_start_addr, uint64_t mod_file_offset,
                              uint64_t elf_sec_start_addr,
                              uint64_t elf_sec_file_offset,
                              uint64_t global_addr);

#ifdef __cplusplus
}
#endif
#endif
