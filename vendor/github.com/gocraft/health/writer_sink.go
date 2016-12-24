package health

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"time"
)

// This sink writes bytes in a format that a human might like to read in a logfile
// This can be used to log to Stdout:
//   .AddSink(&WriterSink{os.Stdout})
// And to a file:
//   f, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
//   .AddSink(&WriterSink{f})
// And to syslog:
//   w, err := syslog.New(LOG_INFO, "wat")
//   .AddSink(&WriterSink{w})
type WriterSink struct {
	io.Writer
}

func (s *WriterSink) EmitEvent(job string, event string, kvs map[string]string) {
	var b bytes.Buffer
	b.WriteRune('[')
	b.WriteString(timestamp())
	b.WriteString("]: job:")
	b.WriteString(job)
	b.WriteString(" event:")
	b.WriteString(event)
	writeMapConsistently(&b, kvs)
	b.WriteRune('\n')
	s.Writer.Write(b.Bytes())
}

func (s *WriterSink) EmitEventErr(job string, event string, inputErr error, kvs map[string]string) {
	var b bytes.Buffer
	b.WriteRune('[')
	b.WriteString(timestamp())
	b.WriteString("]: job:")
	b.WriteString(job)
	b.WriteString(" event:")
	b.WriteString(event)
	b.WriteString(" err:")
	b.WriteString(inputErr.Error())
	writeMapConsistently(&b, kvs)
	b.WriteRune('\n')
	s.Writer.Write(b.Bytes())
}

func (s *WriterSink) EmitTiming(job string, event string, nanos int64, kvs map[string]string) {
	var b bytes.Buffer
	b.WriteRune('[')
	b.WriteString(timestamp())
	b.WriteString("]: job:")
	b.WriteString(job)
	b.WriteString(" event:")
	b.WriteString(event)
	b.WriteString(" time:")
	writeNanoseconds(&b, nanos)
	writeMapConsistently(&b, kvs)
	b.WriteRune('\n')
	s.Writer.Write(b.Bytes())
}

func (s *WriterSink) EmitGauge(job string, event string, value float64, kvs map[string]string) {
	var b bytes.Buffer
	b.WriteRune('[')
	b.WriteString(timestamp())
	b.WriteString("]: job:")
	b.WriteString(job)
	b.WriteString(" event:")
	b.WriteString(event)
	b.WriteString(" gauge:")
	fmt.Fprintf(&b, "%g", value)
	writeMapConsistently(&b, kvs)
	b.WriteRune('\n')
	s.Writer.Write(b.Bytes())
}

func (s *WriterSink) EmitComplete(job string, status CompletionStatus, nanos int64, kvs map[string]string) {
	var b bytes.Buffer
	b.WriteRune('[')
	b.WriteString(timestamp())
	b.WriteString("]: job:")
	b.WriteString(job)
	b.WriteString(" status:")
	b.WriteString(status.String())
	b.WriteString(" time:")
	writeNanoseconds(&b, nanos)
	writeMapConsistently(&b, kvs)
	b.WriteRune('\n')
	s.Writer.Write(b.Bytes())
}

func timestamp() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func writeMapConsistently(b *bytes.Buffer, kvs map[string]string) {
	if kvs == nil {
		return
	}
	keys := make([]string, 0, len(kvs))
	for k := range kvs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	keysLenMinusOne := len(keys) - 1

	b.WriteString(" kvs:[")
	for i, k := range keys {
		b.WriteString(k)
		b.WriteRune(':')
		b.WriteString(kvs[k])

		if i != keysLenMinusOne {
			b.WriteRune(' ')
		}
	}
	b.WriteRune(']')
}

func writeNanoseconds(b *bytes.Buffer, nanos int64) {
	switch {
	case nanos > 2000000:
		fmt.Fprintf(b, "%d ms", nanos/1000000)
	case nanos > 2000:
		fmt.Fprintf(b, "%d μs", nanos/1000)
	default:
		fmt.Fprintf(b, "%d ns", nanos)
	}
}
