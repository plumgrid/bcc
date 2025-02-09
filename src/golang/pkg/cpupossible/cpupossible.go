package cpupossible // import "github.com/iovisor/bcc/pkg/cpupossible"

import (
	"io/ioutil"

	"github.com/iovisor/bcc/pkg/cpurange"
)

const cpuPossible = "/sys/devices/system/cpu/possible"

// Get returns a slice with the online CPUs, for example `[0, 2, 3]`
func Get() ([]uint, error) {
	buf, err := ioutil.ReadFile(cpuPossible)
	if err != nil {
		return nil, err
	}
	return cpurange.ReadCPURange(string(buf))
}
