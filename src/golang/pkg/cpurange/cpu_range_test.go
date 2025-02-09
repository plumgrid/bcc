package cpurange // import "github.com/iovisor/bcc/pkg/cpurange"

import (
	"testing"
)

func TestGetOnlineCPUs(t *testing.T) {
	tests := []struct {
		data     string
		expected []uint
		valid    bool
	}{
		{
			"",
			nil,
			false,
		},
		{
			"0-3\n",
			[]uint{0, 1, 2, 3},
			true,
		},
		{
			"   0-2,5",
			[]uint{0, 1, 2, 5},
			true,
		},
		{
			"0,2,4-5,7-9",
			[]uint{0, 2, 4, 5, 7, 8, 9},
			true,
		},
		{
			"0,2",
			[]uint{0, 2},
			true,
		},
		{
			"0",
			[]uint{0},
			true,
		},
		{
			"-2,5",
			nil,
			false,
		},
		{
			"2-@,5",
			nil,
			false,
		},
		{
			"-",
			nil,
			false,
		},
	}
	for _, test := range tests {
		cpus, err := ReadCPURange(test.data)
		if test.valid && err != nil {
			t.Errorf("expected input %q to not return an error but got: %v\n", test.data, err)
		}
		if !test.valid && err == nil {
			t.Errorf("expected input %q to return an error\n", test.data)
		}
		for i := range cpus {
			if cpus[i] != test.expected[i] {
				t.Errorf("expected %q but got %q\n", test.expected, cpus)
				break
			}
		}
	}
}
