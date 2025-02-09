/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>

#include <dirent.h>
#include <linux/elf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "PyPerfLoggingHelper.h"
#include "PyPerfUtil.h"
#include "bcc_elf.h"
#include "bcc_proc.h"
#include "bcc_syms.h"

namespace ebpf {
namespace pyperf {

extern const OffsetConfig kPy36OffsetConfig;
extern const std::string PYPERF_BPF_PROGRAM;

const static int kPerfBufSizePages = 32;

const static std::string kPidCfgTableName("pid_config");
const static std::string kProgsTableName("progs");
const static std::string kSamplePerfBufName("events");

const static std::string kOnEventFuncName("on_event");

const static std::string kPythonStackFuncName("read_python_stack");
const static std::string kPythonStackProgIdxFlag("-DPYTHON_STACK_PROG_IDX=");
const static int kPythonStackProgIdx = 0;

const static std::string kNumCpusFlag("-DNUM_CPUS=");
const static std::string kSymbolsHashSizeFlag("-D__SYMBOLS_SIZE__=");
const static int kSymbolsHashSize = 16384;

namespace {

bool getRunningPids(std::vector<int>& output) {
  auto dir = ::opendir("/proc/");
  if (!dir) {
    std::fprintf(stderr, "Open /proc failed: %d\n", errno);
    return false;
  }

  dirent* result = nullptr;
  do {
    if ((result = readdir(dir))) {
      std::string basename = result->d_name;
      if (basename == "." || basename == "..") {
        continue;
      }

      std::string fullpath = "/proc/" + basename;
      struct stat st;
      if (::stat(fullpath.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        continue;
      }

      try {
        auto pid = std::stoi(basename);
        output.push_back(pid);
      } catch (const std::exception& e) {
        continue;
      }
    }
  } while (result);

  if (::closedir(dir) == -1) {
    std::fprintf(stderr, "Close /proc failed: %d\n", errno);
    return false;
  }

  return true;
}

typedef struct {
  int pid;
  bool found;
  uint64_t st;
  uint64_t en;
} FindPythonPathHelper;

const static std::string kPy36LibName = "libpython3.6";

int findPythonPathCallback(mod_info *mod, int, void* payload) {
  auto helper = static_cast<FindPythonPathHelper*>(payload);
  std::string file = mod->name;
  auto pos = file.rfind("/");
  if (pos != std::string::npos) {
    file = file.substr(pos + 1);
  }
  if (file.find(kPy36LibName) == 0) {
    logInfo(1, "Found Python library %s loaded at %lx-%lx for PID %d\n", mod->name,
            mod->start_addr, mod->end_addr, helper->pid);
    helper->found = true;
    helper->st = mod->start_addr;
    helper->en = mod->end_addr;
    return -1;
  }
  return 0;
}

bool allAddrFound(const PidData& data) {
  return (data.current_state_addr > 0) && (data.tls_key_addr > 0) &&
         (data.gil_locked_addr > 0) && (data.gil_last_holder_addr > 0);
}

int getAddrOfPythonBinaryCallback(const char* name, uint64_t addr, uint64_t,
                                  void* payload) {
  PidData& data = *static_cast<PidData*>(payload);

  auto checkAndGetAddr = [&](uintptr_t& targetAddr, const char* targetName) {
    if (targetAddr == 0 && std::strcmp(name, targetName) == 0) {
      targetAddr = addr;
    }
  };

  checkAndGetAddr(data.tls_key_addr, "autoTLSkey");
  checkAndGetAddr(data.current_state_addr, "_PyThreadState_Current");
  checkAndGetAddr(data.gil_locked_addr, "gil_locked");
  checkAndGetAddr(data.gil_last_holder_addr, "gil_last_holder");

  if (allAddrFound(data)) {
    return -1;
  }
  return 0;
}

bool getAddrOfPythonBinary(const std::string& path, PidData& data) {
  std::memset(&data, 0, sizeof(data));

  struct bcc_symbol_option option = {.use_debug_file = 0,
                                     .check_debug_file_crc = 0,
                                     .lazy_symbolize = 1,
                                     .use_symbol_type = (1 << STT_OBJECT)};

  bcc_elf_foreach_sym(path.c_str(), &getAddrOfPythonBinaryCallback, &option,
                      &data);

  return allAddrFound(data);
}
}  // namespace

void handleSampleCallback(void* cb_cookie, void* raw_data, int data_size) {
  auto profiler = static_cast<PyPerfUtil*>(cb_cookie);
  profiler->handleSample(raw_data, data_size);
}

void handleLostSamplesCallback(void* cb_cookie, uint64_t lost_cnt) {
  auto profiler = static_cast<PyPerfUtil*>(cb_cookie);
  profiler->handleLostSamples(lost_cnt);
}

PyPerfUtil::PyPerfResult PyPerfUtil::init() {
  std::vector<std::string> cflags;
  cflags.emplace_back(kNumCpusFlag +
                      std::to_string(::sysconf(_SC_NPROCESSORS_ONLN)));
  cflags.emplace_back(kSymbolsHashSizeFlag + std::to_string(kSymbolsHashSize));
  cflags.emplace_back(kPythonStackProgIdxFlag +
                      std::to_string(kPythonStackProgIdx));

  auto initRes = bpf_.init(PYPERF_BPF_PROGRAM, cflags);
  if (!initRes.ok()) {
    std::fprintf(stderr, "Failed to compiled PyPerf BPF programs: %s\n",
                 initRes.msg().c_str());
    return PyPerfResult::INIT_FAIL;
  }

  int progFd = -1;
  auto loadRes =
      bpf_.load_func(kPythonStackFuncName, BPF_PROG_TYPE_PERF_EVENT, progFd);
  if (!loadRes.ok()) {
    std::fprintf(stderr, "Failed to load BPF program %s: %s\n",
                 kPythonStackFuncName.c_str(), loadRes.msg().c_str());
    return PyPerfResult::INIT_FAIL;
  }

  auto progTable = bpf_.get_prog_table(kProgsTableName);
  auto updateRes = progTable.update_value(kPythonStackProgIdx, progFd);
  if (!updateRes.ok()) {
    std::fprintf(stderr,
                 "Failed to set BPF program %s FD %d to program table: %s\n",
                 kPythonStackFuncName.c_str(), progFd, updateRes.msg().c_str());
    return PyPerfResult::INIT_FAIL;
  }

  std::vector<int> pids;
  if (!getRunningPids(pids)) {
    std::fprintf(stderr, "Failed getting running Processes\n");
    return PyPerfResult::INIT_FAIL;
  }

  // Populate config for each Python Process
  auto pid_hash = bpf_.get_hash_table<int, PidData>(kPidCfgTableName);
  PidData pidData;
  for (const auto pid : pids) {
    if (!tryTargetPid(pid, pidData)) {
      // Not a Python Process
      continue;
    }
    pid_hash.update_value(pid, pidData);
  }

  // Open perf buffer
  auto openRes = bpf_.open_perf_buffer(
      kSamplePerfBufName, &handleSampleCallback, &handleLostSamplesCallback,
      this, kPerfBufSizePages);
  if (!openRes.ok()) {
    std::fprintf(stderr, "Unable to open Perf Buffer: %s\n",
                 openRes.msg().c_str());
    return PyPerfResult::PERF_BUF_OPEN_FAIL;
  }

  initCompleted_ = true;
  return PyPerfResult::SUCCESS;
}

void PyPerfUtil::handleSample(const void* data, int dataSize) {
  const Event* raw = static_cast<const Event*>(data);
  samples_.emplace_back(raw, dataSize);
  totalSamples_++;
}

void PyPerfUtil::handleLostSamples(int lostCnt) { lostSamples_ += lostCnt; }

PyPerfUtil::PyPerfResult PyPerfUtil::profile(int64_t sampleRate,
                                             int64_t durationMs,
                                             PyPerfSampleProcessor* processor) {
  if (!initCompleted_) {
    std::fprintf(stderr, "PyPerfUtil::init not invoked or failed\n");
    return PyPerfResult::NO_INIT;
  }

  // Attach to CPU cycles
  auto attachRes =
      bpf_.attach_perf_event(0, 0, kOnEventFuncName, sampleRate, 0);
  if (!attachRes.ok()) {
    std::fprintf(stderr, "Attach to CPU cycles event failed: %s\n",
                 attachRes.msg().c_str());
    return PyPerfResult::EVENT_ATTACH_FAIL;
  }
  logInfo(2, "Attached to profiling event\n");

  // Get Perf Buffer and poll in a loop for a given duration
  auto perfBuffer = bpf_.get_perf_buffer(kSamplePerfBufName);
  if (!perfBuffer) {
    std::fprintf(stderr, "Failed to get Perf Buffer: %s\n",
                 kSamplePerfBufName.c_str());
    return PyPerfResult::PERF_BUF_OPEN_FAIL;
  }
  logInfo(2, "Started polling Perf Buffer\n");
  auto start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() <
         start + std::chrono::milliseconds(durationMs)) {
    perfBuffer->poll(50 /* 50ms timeout */);
  }
  logInfo(2, "Profiling duration finished\n");

  // Detach the event
  auto detachRes = bpf_.detach_perf_event(0, 0);
  if (!detachRes.ok()) {
    std::fprintf(stderr, "Detach CPU cycles event failed: %s\n",
                 detachRes.msg().c_str());
    return PyPerfResult::EVENT_DETACH_FAIL;
  }
  logInfo(2, "Detached from profiling event\n");

  // Drain remaining samples
  logInfo(2, "Draining remaining samples\n");
  while (perfBuffer->poll(0) > 0) {
  }
  logInfo(2, "Finished draining remaining samples\n");

  processor->processSamples(samples_, this);

  return PyPerfResult::SUCCESS;
}

std::unordered_map<int32_t, std::string> PyPerfUtil::getSymbolMapping() {
  auto symbolTable = bpf_.get_hash_table<Symbol, int32_t>("symbols");
  std::unordered_map<int32_t, std::string> symbols;
  for (auto& x : symbolTable.get_table_offline()) {
    auto symbolName = getSymbolName(x.first);
    logInfo(2, "Symbol ID %d is %s\n", x.second, symbolName.c_str());
    symbols.emplace(x.second, std::move(symbolName));
  }
  logInfo(1, "Total %d unique Python symbols\n", symbols.size());
  return symbols;
}

std::string PyPerfUtil::getSymbolName(Symbol& sym) const {
  std::string nameStr = std::string(sym.name).substr(0, FUNCTION_NAME_LEN);
  std::string classStr = std::string(sym.classname).substr(0, CLASS_NAME_LEN);
  if (classStr.size() > 0) {
    nameStr = classStr + "." + nameStr;
  }

  std::string file = std::string(sym.file).substr(0, FILE_NAME_LEN);
  if (file.empty()) {
    return nameStr;
  }
  if (file[0] == '/') {
    file = file.substr(1);
  }
  if (file.find("./") == 0) {
    file = file.substr(2);
  }
  if (file.find(".py", file.size() - 3) == (file.size() - 3)) {
    file = file.substr(0, file.size() - 3);
  }
  std::replace(file.begin(), file.end(), '/', '.');

  return file + "." + nameStr;
}

bool PyPerfUtil::tryTargetPid(int pid, PidData& data) {
  FindPythonPathHelper helper{pid, false, 0, 0};
  bcc_procutils_each_module(pid, &findPythonPathCallback, &helper);
  if (!helper.found) {
    logInfo(2, "PID %d does not contain Python library\n", pid);
    return false;
  }

  char path[256];
  int res = std::snprintf(path, sizeof(path), "/proc/%d/map_files/%lx-%lx", pid,
                          helper.st, helper.en);
  if (res < 0 || size_t(res) >= sizeof(path)) {
    return false;
  }

  if (!getAddrOfPythonBinary(path, data)) {
    std::fprintf(
        stderr,
        "Failed getting addresses in potential Python library in PID %d\n",
        pid);
    return false;
  }
  data.offsets = kPy36OffsetConfig;
  data.current_state_addr += helper.st;
  logInfo(2, "PID %d has _PyThreadState_Current at %lx\n", pid,
          data.current_state_addr);
  data.tls_key_addr += helper.st;
  logInfo(2, "PID %d has autoTLSKey at %lx\n", pid, data.current_state_addr);
  data.gil_locked_addr += helper.st;
  logInfo(2, "PID %d has gil_locked at %lx\n", pid, data.current_state_addr);
  data.gil_last_holder_addr += helper.st;
  logInfo(2, "PID %d has gil_last_holder at %lx\n", pid,
          data.current_state_addr);

  return true;
}

}  // namespace pyperf
}  // namespace ebpf
