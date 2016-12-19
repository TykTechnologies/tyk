/*
Copyright (c) 2014 Ashley Jeffs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package tunny

import (
	"sync/atomic"
	"time"
)

type workerWrapper struct {
	readyChan  chan int
	jobChan    chan interface{}
	outputChan chan interface{}
	poolOpen   uint32
	worker     TunnyWorker
}

func (wrapper *workerWrapper) Loop() {

	// TODO: Configure?
	tout := time.Duration(5)

	for !wrapper.worker.TunnyReady() {
		// It's sad that we can't simply check if jobChan is closed here.
		if atomic.LoadUint32(&wrapper.poolOpen) == 0 {
			break
		}
		time.Sleep(tout * time.Millisecond)
	}

	wrapper.readyChan <- 1

	for data := range wrapper.jobChan {
		wrapper.outputChan <- wrapper.worker.TunnyJob(data)
		for !wrapper.worker.TunnyReady() {
			if atomic.LoadUint32(&wrapper.poolOpen) == 0 {
				break
			}
			time.Sleep(tout * time.Millisecond)
		}
		wrapper.readyChan <- 1
	}

	close(wrapper.readyChan)
	close(wrapper.outputChan)

}

func (wrapper *workerWrapper) Open() {
	if extWorker, ok := wrapper.worker.(TunnyExtendedWorker); ok {
		extWorker.TunnyInitialize()
	}

	wrapper.readyChan = make(chan int)
	wrapper.jobChan = make(chan interface{})
	wrapper.outputChan = make(chan interface{})

	atomic.SwapUint32(&wrapper.poolOpen, uint32(1))

	go wrapper.Loop()
}

// Follow this with Join(), otherwise terminate isn't called on the worker
func (wrapper *workerWrapper) Close() {
	close(wrapper.jobChan)

	// Breaks the worker out of a Ready() -> false loop
	atomic.SwapUint32(&wrapper.poolOpen, uint32(0))
}

func (wrapper *workerWrapper) Join() {
	// Ensure that both the ready and output channels are closed
	for {
		_, readyOpen := <-wrapper.readyChan
		_, outputOpen := <-wrapper.outputChan
		if !readyOpen && !outputOpen {
			break
		}
	}

	if extWorker, ok := wrapper.worker.(TunnyExtendedWorker); ok {
		extWorker.TunnyTerminate()
	}
}

func (wrapper *workerWrapper) Interrupt() {
	if extWorker, ok := wrapper.worker.(TunnyInterruptable); ok {
		extWorker.TunnyInterrupt()
	}
}
