// Copyright 2016 PLUMgrid
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

package test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"testing"
	"unsafe"

	bcc "github.com/iovisor/bcc"
)

var simple1 string = `
BPF_TABLE("hash", int, int, table1, 10);
int func1(void *ctx) {
	return 0;
}
`

var simple2 = `
struct key {
  int key;
};
struct leaf {
  int value;
};
BPF_HASH(table2, struct key, struct leaf, 10);
int func2(void *ctx) {
	return 0;
}
`

type key struct {
	key uint32
}

type leaf struct {
	value uint32
}

func TestModuleLoadBCC(t *testing.T) {
	b := bcc.NewModule(simple1, []string{})
	if b == nil {
		t.Fatal("prog is nil")
	}
	defer b.Close()
	_, err := b.LoadKprobe("func1")
	if err != nil {
		t.Fatal(err)
	}
}

func fillTable1(b *bcc.Module) (*bcc.Table, error) {
	table := bcc.NewTable(b.TableId("table1"), b)
	key, _ := table.KeyStrToBytes("1")
	leaf, _ := table.LeafStrToBytes("11")
	if err := table.Set(key, leaf); err != nil {
		return nil, fmt.Errorf("table.Set key 1 failed: %v", err)
	}

	key, leaf = make([]byte, 4), make([]byte, 4)
	bcc.GetHostByteOrder().PutUint32(key, 2)
	bcc.GetHostByteOrder().PutUint32(leaf, 22)
	if err := table.Set(key, leaf); err != nil {
		return nil, fmt.Errorf("table.Set key 2 failed: %v", err)
	}

	return table, nil
}

func TestBCCIterTable(t *testing.T) {
	b := bcc.NewModule(simple1, []string{})
	if b == nil {
		t.Fatal("prog is nil")
	}
	defer b.Close()

	table, err := fillTable1(b)
	if err != nil {
		t.Fatalf("fill table1 failed: %v", err)
	}

	hostEndian := bcc.GetHostByteOrder()
	resIter := make(map[int32]int32)
	iter := table.Iter()
	for iter.Next() {
		key, leaf := iter.Key(), iter.Leaf()
		keyStr, err := table.KeyBytesToStr(key)
		if err != nil {
			t.Fatalf("table.Iter/KeyBytesToStr failed: cannot print value: %v", err)
		}
		leafStr, err := table.LeafBytesToStr(leaf)
		if err != nil {
			t.Fatalf("table.Iter/LeafBytesToStr failed: cannot print value: %v", err)
		}

		var k, v int32
		if err := binary.Read(bytes.NewBuffer(key), hostEndian, &k); err != nil {
			t.Fatalf("table.Iter failed: cannot decode key: %v", err)
		}
		if err := binary.Read(bytes.NewBuffer(leaf), hostEndian, &v); err != nil {
			t.Fatalf("table.Iter failed: cannot decode value: %v", err)
		}

		resIter[k] = v

		kS, err := strconv.ParseInt(keyStr[2:], 16, 32)
		if err != nil {
			t.Fatalf("table.Iter failed: non-number key: %v", err)
		}
		vS, err := strconv.ParseInt(leafStr[2:], 16, 32)
		if err != nil {
			t.Fatalf("table.Iter failed: non-number value: %v", err)
		}

		if int32(kS) != k || int32(vS) != v {
			t.Errorf("table.iter.Values() inconsistent with string values: (%v, %v) vs (%v, %v)", k, v, kS, vS)
		}
	}

	if iter.Err() != nil {
		t.Fatalf("table.Iter failed: iteration finished with unexpected error: %v", iter.Err())
	}

	if count := len(resIter); count != 2 {
		t.Fatalf("expected 2 entries in Iter table, not %d", count)
	}

	for _, te := range [][]int32{{1, 11}, {2, 22}} {
		res := resIter[te[0]]
		if res != te[1] {
			t.Fatalf("expected entry %d in Iter table to contain %d, but got %d", te[0], te[1], res)
		}
	}
}

func TestBCCTableSetPGetPDeleteP(t *testing.T) {
	b := bcc.NewModule(simple2, []string{})
	if b == nil {
		t.Fatal("prog is nil")
	}
	defer b.Close()

	table := bcc.NewTable(b.TableId("table2"), b)

	k := &key{0}
	l := &leaf{1}

	err := table.SetP(unsafe.Pointer(k), unsafe.Pointer(l))
	if err != nil {
		t.Fatal(err)
	}

	p, err := table.GetP(unsafe.Pointer(k))
	if err != nil {
		t.Fatal(err)
	}
	v := (*leaf)(p)
	if v.value != 1 {
		t.Fatalf("expected 1, not %d", v.value)
	}

	err = table.DeleteP(unsafe.Pointer(k))
	if err != nil {
		t.Fatal(err)
	}

	_, err = table.GetP(unsafe.Pointer(k))
	if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestBCCTableDeleteAll(t *testing.T) {
	b := bcc.NewModule(simple1, []string{})
	if b == nil {
		t.Fatal("prog is nil")
	}
	defer b.Close()

	table, err := fillTable1(b)
	if err != nil {
		t.Fatalf("fill table1 failed: %v", err)
	}

	count := 0
	for it := table.Iter(); it.Next(); {
		count++
	}
	if count != 2 {
		t.Fatalf("expected 2 entries in table, not %d", count)
	}
	if err := table.DeleteAll(); err != nil {
		t.Fatalf("table.DeleteAll failed: %v", err)
	}
	count = 0
	for it := table.Iter(); it.Next(); {
		count++
	}
	if count != 0 {
		t.Fatalf("expected 0 entries in table, not %d", count)
	}
}
