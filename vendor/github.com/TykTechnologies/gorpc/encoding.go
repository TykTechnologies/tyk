package gorpc

import (
	"bufio"
	"compress/flate"
	"encoding/gob"
	"io"
)

// RegisterType registers the given type to send via rpc.
//
// The client must register all the response types the server may send.
// The server must register all the request types the client may send.
//
// There is no need in registering base Go types such as int, string, bool,
// float64, etc. or arrays, slices and maps containing base Go types.
//
// There is no need in registering argument and return value types
// for functions and methods registered via Dispatcher.
func RegisterType(x interface{}) {
	gob.Register(x)
}

type wireRequest struct {
	ID      uint64
	Request interface{}
}

type wireResponse struct {
	ID       uint64
	Response interface{}
	Error    string
}

type messageEncoder struct {
	e  *gob.Encoder
	bw *bufio.Writer
	zw *flate.Writer
	ww *bufio.Writer
}

func (e *messageEncoder) Close() error {
	if e.zw != nil {
		return e.zw.Close()
	}
	return nil
}

func (e *messageEncoder) Flush() error {
	if e.zw != nil {
		if err := e.ww.Flush(); err != nil {
			return err
		}
		if err := e.zw.Flush(); err != nil {
			return err
		}
	}
	if err := e.bw.Flush(); err != nil {
		return err
	}
	return nil
}

func (e *messageEncoder) Encode(msg interface{}) error {
	return e.e.Encode(msg)
}

func newMessageEncoder(w io.Writer, bufferSize int, enableCompression bool, s *ConnStats) *messageEncoder {
	w = newWriterCounter(w, s)
	bw := bufio.NewWriterSize(w, bufferSize)

	ww := bw
	var zw *flate.Writer
	if enableCompression {
		zw, _ = flate.NewWriter(bw, flate.BestSpeed)
		ww = bufio.NewWriterSize(zw, bufferSize)
	}

	return &messageEncoder{
		e:  gob.NewEncoder(ww),
		bw: bw,
		zw: zw,
		ww: ww,
	}
}

type messageDecoder struct {
	d  *gob.Decoder
	zr io.ReadCloser
}

func (d *messageDecoder) Close() error {
	if d.zr != nil {
		return d.zr.Close()
	}
	return nil
}

func (d *messageDecoder) Decode(msg interface{}) error {
	return d.d.Decode(msg)
}

func newMessageDecoder(r io.Reader, bufferSize int, enableCompression bool, s *ConnStats) *messageDecoder {
	r = newReaderCounter(r, s)
	br := bufio.NewReaderSize(r, bufferSize)

	rr := br
	var zr io.ReadCloser
	if enableCompression {
		zr = flate.NewReader(br)
		rr = bufio.NewReaderSize(zr, bufferSize)
	}

	return &messageDecoder{
		d:  gob.NewDecoder(rr),
		zr: zr,
	}
}
