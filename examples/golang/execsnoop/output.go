package main

import (
	"encoding/json"
	"fmt"
	"time"
)

type output interface {
	PrintHeader()
	PrintLine(eventPayload)
}

type timing struct {
	start time.Time
}

func newTiming() timing {
	return timing{time.Now()}
}

func (t timing) Now() float64 {
	return time.Now().Sub(t.start).Seconds()
}

func newOutput(name string, pretty, timestamp bool) output {
	switch name {
	case "json":
		return newJSONOutput(pretty, timestamp)
	}
	return newTableOutput(timestamp)
}

type tableOutput struct {
	timing    timing
	timestamp bool
}

func (t tableOutput) PrintHeader() {
	header := "%-16s %-7s %-7s %3s %s\n"
	args := []interface{}{"PCOMM", "PID", "PPID", "RET", "ARGS"}
	if t.timestamp {
		header = "%-8s" + header
		args = []interface{}{"TIME(s)", "PCOMM", "PID", "PPID", "RET", "ARGS"}
	}
	fmt.Printf(header, args...)
}

func (t tableOutput) PrintLine(e eventPayload) {
	header := "%-16s %-7d %-7s %3d %s\n"
	args := []interface{}{e.Comm, e.Pid, e.Ppid, e.RetVal, e.Argv}
	if t.timestamp {
		header = "%-8.3f" + header
		args = append([]interface{}{t.timing.Now()}, args...)
	}
	fmt.Printf(header, args...)
}

func newTableOutput(timestamp bool) output {
	return &tableOutput{newTiming(), timestamp}
}

type jsonOutput struct {
	timing    timing
	pretty    bool
	timestamp bool
}

func (jsonOutput) PrintHeader() {
	// jsonOutput doesn't have any header
}

func (j jsonOutput) PrintLine(e eventPayload) {
	if j.timestamp {
		e.Time = fmt.Sprintf("%.3f", j.timing.Now())
	}
	var m []byte
	if j.pretty {
		m, _ = json.MarshalIndent(e, "", "  ")
	} else {
		m, _ = json.Marshal(e)
	}
	if len(m) > 0 {
		fmt.Println(string(m))
	}
}

func newJSONOutput(pretty, timestamp bool) output {
	return jsonOutput{newTiming(), pretty, timestamp}
}
