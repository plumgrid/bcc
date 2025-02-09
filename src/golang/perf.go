// Copyright 2016 Kinvolk
// Copyright 2023 Microsoft
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bcc

import (
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"github.com/iovisor/bcc/pkg/cpuonline"
)

/*
#cgo pkg-config: libbcc
#ifdef LOCAL
#include <bcc_common.h>
#include <libbpf.h>
#include <perf_reader.h>
#else
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
#include <bcc/perf_reader.h>
#endif

// perf_reader_raw_cb and perf_reader_lost_cb as defined in bcc libbpf.h
// typedef void (*perf_reader_raw_cb)(void *cb_cookie, void *raw, int raw_size);
extern void rawCallback(void*, void*, int);
// typedef void (*perf_reader_lost_cb)(void *cb_cookie, uint64_t lost);
extern void lostCallback(void*, uint64_t);
*/
import "C"

type PerfMap struct {
	table   *Table
	readers []*C.struct_perf_reader
	stop    chan bool
}

type callbackData struct {
	receiverChan chan []byte
	lostChan     chan uint64
}

// BPF_PERF_READER_PAGE_CNT is the default page_cnt used per cpu ring buffer
const BPF_PERF_READER_PAGE_CNT = 8

var byteOrder binary.ByteOrder
var callbackRegister = make(map[uint64]*callbackData)
var callbackIndex uint64
var mu sync.Mutex

// In lack of binary.HostEndian ...
func init() {
	byteOrder = determineHostByteOrder()
}

func registerCallback(data *callbackData) uint64 {
	mu.Lock()
	defer mu.Unlock()
	callbackIndex++
	for callbackRegister[callbackIndex] != nil {
		callbackIndex++
	}
	callbackRegister[callbackIndex] = data
	return callbackIndex
}

func unregisterCallback(i uint64) {
	mu.Lock()
	defer mu.Unlock()
	delete(callbackRegister, i)
}

func lookupCallback(i uint64) *callbackData {
	return callbackRegister[i]
}

// Gateway function as required with CGO Go >= 1.6
// "If a C-program wants a function pointer, a gateway function has to
// be written. This is because we can't take the address of a Go
// function and give that to C-code since the cgo tool will generate a
// stub in C that should be called."
//
//export rawCallback
func rawCallback(cbCookie unsafe.Pointer, raw unsafe.Pointer, rawSize C.int) {
	callbackData := lookupCallback(uint64(uintptr(cbCookie)))
	callbackData.receiverChan <- C.GoBytes(raw, rawSize)
}

//export lostCallback
func lostCallback(cbCookie unsafe.Pointer, lost C.uint64_t) {
	callbackData := lookupCallback(uint64(uintptr(cbCookie)))
	if callbackData.lostChan != nil {
		callbackData.lostChan <- uint64(lost)
	}
}

// GetHostByteOrder returns the current byte-order.
func GetHostByteOrder() binary.ByteOrder {
	return byteOrder
}

func determineHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

// InitPerfMap initializes a perf map with a receiver channel, with a default page_cnt.
func InitPerfMap(table *Table, receiverChan chan []byte, lostChan chan uint64) (*PerfMap, error) {
	return InitPerfMapWithPageCnt(table, receiverChan, lostChan, BPF_PERF_READER_PAGE_CNT)
}

// InitPerfMapWithPageCnt initializes a perf map with a receiver channel with a specified page_cnt.
func InitPerfMapWithPageCnt(table *Table, receiverChan chan []byte, lostChan chan uint64, pageCnt int) (*PerfMap, error) {
	fd := table.Config()["fd"].(int)
	keySize := table.Config()["key_size"].(uint64)
	leafSize := table.Config()["leaf_size"].(uint64)

	if keySize != 4 || leafSize != 4 {
		return nil, fmt.Errorf("passed table has wrong size")
	}

	callbackDataIndex := registerCallback(&callbackData{
		receiverChan,
		lostChan,
	})

	key := make([]byte, keySize)
	leaf := make([]byte, leafSize)
	keyP := unsafe.Pointer(&key[0])
	leafP := unsafe.Pointer(&leaf[0])

	readers := []*C.struct_perf_reader{}

	cpus, err := cpuonline.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to determine online cpus: %v", err)
	}

	for _, cpu := range cpus {
		reader, err := bpfOpenPerfBuffer(cpu, callbackDataIndex, pageCnt)
		if err != nil {
			return nil, fmt.Errorf("failed to open perf buffer: %v", err)
		}

		perfFd := C.perf_reader_fd((*C.struct_perf_reader)(reader))

		readers = append(readers, (*C.struct_perf_reader)(reader))

		byteOrder.PutUint32(leaf, uint32(perfFd))

		r, err := C.bpf_update_elem(C.int(fd), keyP, leafP, 0)
		if r != 0 {
			return nil, fmt.Errorf("unable to initialize perf map: %v", err)
		}
		r = C.bpf_get_next_key(C.int(fd), keyP, keyP)
		if r != 0 {
			break
		}
	}
	return &PerfMap{
		table,
		readers,
		make(chan bool),
	}, nil
}

// Start to poll the perf map reader and send back event data
// over the connected channel.
func (pm *PerfMap) Start() {
	go pm.poll(500)
}

// Stop to poll the perf map readers after a maximum of 500ms
// (the timeout we use for perf_reader_poll). Ideally we would
// have a way to cancel the poll, but perf_reader_poll doesn't
// support that yet.
func (pm *PerfMap) Stop() {
	pm.stop <- true
}

func (pm *PerfMap) poll(timeout int) {
	for {
		select {
		case <-pm.stop:
			return
		default:
			C.perf_reader_poll(C.int(len(pm.readers)), &pm.readers[0], C.int(timeout))
		}
	}
}

func bpfOpenPerfBuffer(cpu uint, callbackDataIndex uint64, pageCnt int) (unsafe.Pointer, error) {
	if (pageCnt & (pageCnt - 1)) != 0 {
		return nil, fmt.Errorf("pageCnt must be a power of 2: %d", pageCnt)
	}
	cpuC := C.int(cpu)
	pageCntC := C.int(pageCnt)
	reader, err := C.bpf_open_perf_buffer(
		(C.perf_reader_raw_cb)(unsafe.Pointer(C.rawCallback)),
		(C.perf_reader_lost_cb)(unsafe.Pointer(C.lostCallback)),
		unsafe.Pointer(uintptr(callbackDataIndex)),
		-1, cpuC, pageCntC)
	if reader == nil {
		return nil, fmt.Errorf("failed to open perf buffer: %v", err)
	}
	return reader, nil
}
