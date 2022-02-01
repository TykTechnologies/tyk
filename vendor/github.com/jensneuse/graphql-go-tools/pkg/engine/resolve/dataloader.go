package resolve

import (
	"fmt"
	"sync"

	"github.com/buger/jsonparser"

	"github.com/jensneuse/graphql-go-tools/pkg/fastbuffer"
)

const (
	initialValueID  = -1
	arrayElementKey = "@"
)

// dataLoaderFactory is responsible for creating dataloader and provides different pools (e.g, bufPair,
// bufPairSlice, waitGroup pools).
type dataLoaderFactory struct {
	dataloaderPool   sync.Pool
	muPool           sync.Pool
	waitGroupPool    sync.Pool
	bufPairPool      sync.Pool
	bufPairSlicePool sync.Pool

	fetcher *Fetcher
}

func (df *dataLoaderFactory) getWaitGroup() *sync.WaitGroup {
	return df.waitGroupPool.Get().(*sync.WaitGroup)
}

func (df *dataLoaderFactory) freeWaitGroup(wg *sync.WaitGroup) {
	df.waitGroupPool.Put(wg)
}

func (df *dataLoaderFactory) getBufPairSlicePool() *[]*BufPair {
	return df.bufPairSlicePool.Get().(*[]*BufPair)
}

func (df *dataLoaderFactory) freeBufPairSlice(slice *[]*BufPair) {
	for i := range *slice {
		df.freeBufPair((*slice)[i])
	}
	*slice = (*slice)[:0]
	df.bufPairSlicePool.Put(slice)
}

func (df *dataLoaderFactory) getBufPair() *BufPair {
	return df.bufPairPool.Get().(*BufPair)
}

func (df *dataLoaderFactory) freeBufPair(pair *BufPair) {
	pair.Data.Reset()
	pair.Errors.Reset()
	df.bufPairPool.Put(pair)
}

func (df *dataLoaderFactory) getMutex() *sync.Mutex {
	return df.muPool.Get().(*sync.Mutex)
}

func (df *dataLoaderFactory) freeMutex(mu *sync.Mutex) {
	df.muPool.Put(mu)
}

func newDataloaderFactory(fetcher *Fetcher) *dataLoaderFactory {
	return &dataLoaderFactory{
		muPool: sync.Pool{
			New: func() interface{} {
				return &sync.Mutex{}
			},
		},
		waitGroupPool: sync.Pool{
			New: func() interface{} {
				return &sync.WaitGroup{}
			},
		},
		bufPairPool: sync.Pool{
			New: func() interface{} {
				pair := BufPair{
					Data:   fastbuffer.New(),
					Errors: fastbuffer.New(),
				}
				return &pair
			},
		},
		bufPairSlicePool: sync.Pool{
			New: func() interface{} {
				slice := make([]*BufPair, 0, 24)
				return &slice
			},
		},
		dataloaderPool: sync.Pool{
			New: func() interface{} {
				return &dataLoader{
					fetches:      make(map[int]fetchState),
					inUseBufPair: make([]*BufPair, 0, 8),
				}
			},
		},
		fetcher: fetcher,
	}
}

// newDataLoader returns new instance of dataLoader.
// initialValue represents data from subscription, initialValue will be saved with initialValueID id and could be used
// for further fetches.
func (df *dataLoaderFactory) newDataLoader(initialValue []byte) *dataLoader {
	dataloader := df.dataloaderPool.Get().(*dataLoader)

	dataloader.mu = df.getMutex()
	dataloader.resourceProvider = df
	dataloader.fetcher = df.fetcher

	if initialValue != nil {

		buf := dataloader.getResultBufPair()
		buf.Data.WriteBytes(initialValue)

		dataloader.fetches[initialValueID] = &batchFetchState{
			nextIdx:    0,
			fetchError: nil,
			results:    []*BufPair{buf},
		}
	}

	return dataloader
}

func (df *dataLoaderFactory) freeDataLoader(d *dataLoader) {
	for _, pair := range d.inUseBufPair {
		d.resourceProvider.freeBufPair(pair)
	}

	d.resourceProvider.freeMutex(d.mu)

	d.inUseBufPair = d.inUseBufPair[:0]
	d.fetches = nil
}

// dataLoader
type dataLoader struct {
	fetches          map[int]fetchState
	mu               *sync.Mutex
	fetcher          *Fetcher
	resourceProvider *dataLoaderFactory

	inUseBufPair []*BufPair
}

// Load fetches concurrently data for all siblings.
func (d *dataLoader) Load(ctx *Context, fetch *SingleFetch, responsePair *BufPair) (err error) {
	var fetchResult fetchState
	var resultPair *BufPair

	fetchResult, ok := d.getFetchState(fetch.BufferId)
	if ok {
		resultPair, err = fetchResult.next(ctx)
		copyBufPair(responsePair, resultPair)
		return
	}

	fetchResult = &batchFetchState{}

	parentResult, ok := d.getFetchState(ctx.lastFetchID)

	if !ok { // it must be root query without subscription data
		buf := d.resourceProvider.getBufPair()
		defer d.resourceProvider.freeBufPair(buf)

		if err := fetch.InputTemplate.Render(ctx, nil, buf.Data); err != nil {
			return err
		}

		pair := d.getResultBufPair()
		err = d.fetcher.Fetch(ctx, fetch, buf.Data, pair)
		fetchResult = &singleFetchState{
			fetchErrors: []error{err},
			results:     []*BufPair{pair},
		}

		d.setFetchState(fetchResult, fetch.BufferId)

		resultPair, err = fetchResult.next(ctx)
		copyBufPair(responsePair, resultPair)
		return
	}

	fetchParams, err := d.selectedDataForFetch(parentResult.data(), ctx.responseElements...)
	if err != nil {
		return err
	}

	if fetchResult, err = d.resolveSingleFetch(ctx, fetch, fetchParams); err != nil {
		return err
	}

	d.setFetchState(fetchResult, fetch.BufferId)

	resultPair, err = fetchResult.next(ctx)
	copyBufPair(responsePair, resultPair)

	return
}

// LoadBatch builds and resolve batch request for all siblings.
func (d *dataLoader) LoadBatch(ctx *Context, batchFetch *BatchFetch, responsePair *BufPair) (err error) {
	var fetchResult fetchState
	var resultPair *BufPair
	fetchResult, ok := d.getFetchState(batchFetch.Fetch.BufferId)
	if ok {
		resultPair, err = fetchResult.next(ctx)
		copyBufPair(responsePair, resultPair)
		return
	}

	fetchResult = &batchFetchState{}

	parentResult, ok := d.getFetchState(ctx.lastFetchID)
	if !ok {
		return fmt.Errorf("has not got fetch for %d", ctx.lastFetchID)
	}

	fetchParams, err := d.selectedDataForFetch(parentResult.data(), ctx.responseElements...)
	if err != nil {
		return err
	}

	if fetchResult, err = d.resolveBatchFetch(ctx, batchFetch, fetchParams); err != nil {
		return err
	}

	d.setFetchState(fetchResult, batchFetch.Fetch.BufferId)

	resultPair, err = fetchResult.next(ctx)
	copyBufPair(responsePair, resultPair)
	return
}

func (d *dataLoader) resolveBatchFetch(ctx *Context, batchFetch *BatchFetch, fetchParams [][]byte) (fetchState *batchFetchState, err error) {
	inputBufs := make([]*fastbuffer.FastBuffer, 0, len(fetchParams))

	bufSlice := d.resourceProvider.getBufPairSlicePool()
	defer d.resourceProvider.freeBufPairSlice(bufSlice)

	for i := range fetchParams {
		bufPair := d.resourceProvider.getBufPair()
		*bufSlice = append(*bufSlice, bufPair)
		if err := batchFetch.Fetch.InputTemplate.Render(ctx, fetchParams[i], bufPair.Data); err != nil {
			return nil, err
		}

		inputBufs = append(inputBufs, bufPair.Data)
	}

	outBuf := d.resourceProvider.getBufPair()
	*bufSlice = append(*bufSlice, outBuf)

	results := make([]*BufPair, len(inputBufs))
	for i := range inputBufs {
		results[i] = d.getResultBufPair()
	}

	fetchState = &batchFetchState{}

	if err = d.fetcher.FetchBatch(ctx, batchFetch, inputBufs, results); err != nil {
		fetchState.fetchError = err
		return fetchState, nil
	}

	fetchState.results = results

	return fetchState, nil
}

func (d *dataLoader) resolveSingleFetch(ctx *Context, fetch *SingleFetch, fetchParams [][]byte) (fetchState *singleFetchState, err error) {
	wg := d.resourceProvider.getWaitGroup()
	defer d.resourceProvider.freeWaitGroup(wg)

	wg.Add(len(fetchParams))

	type fetchResult struct {
		result *BufPair
		err    error
		pos    int
	}

	resultCh := make(chan fetchResult, len(fetchParams))

	bufSlice := d.resourceProvider.getBufPairSlicePool()
	defer d.resourceProvider.freeBufPairSlice(bufSlice)

	for i, val := range fetchParams {
		bufPair := d.resourceProvider.getBufPair()
		*bufSlice = append(*bufSlice, bufPair)
		if err := fetch.InputTemplate.Render(ctx, val, bufPair.Data); err != nil {
			return nil, err
		}

		pair := d.getResultBufPair()

		go func(pos int, pair *BufPair) {
			err := d.fetcher.Fetch(ctx, fetch, bufPair.Data, pair)
			resultCh <- fetchResult{result: pair, err: err, pos: pos}
			wg.Done()
		}(i, pair)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	fetchState = &singleFetchState{
		fetchErrors: make([]error, len(fetchParams)),
		results:     make([]*BufPair, len(fetchParams)),
	}

	for res := range resultCh {
		fetchState.fetchErrors[res.pos] = res.err
		fetchState.results[res.pos] = res.result
	}

	return fetchState, err
}

func (d *dataLoader) getFetchState(fetchID int) (batchState fetchState, ok bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	batchState, ok = d.fetches[fetchID]
	return
}

func (d *dataLoader) setFetchState(batchState fetchState, fetchID int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.fetches[fetchID] = batchState
}

func (d *dataLoader) selectedDataForFetch(input [][]byte, path ...string) ([][]byte, error) {
	if len(path) == 0 {
		return input, nil
	}

	current, rest := path[0], path[1:]

	if current == arrayElementKey {
		return flatMap(input, func(val []byte) ([][]byte, error) {
			var vals [][]byte
			_, err := jsonparser.ArrayEach(val, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
				vals = append(vals, value)
			})
			if err != nil { // In case if array is null
				return nil, nil
			}

			return d.selectedDataForFetch(vals, rest...)
		})
	}

	temp := make([][]byte, 0, len(input))

	for i := range input {
		el, _, _, err := jsonparser.Get(input[i], current)
		if err != nil {
			return nil, err
		}
		temp = append(temp, el)
	}

	return d.selectedDataForFetch(temp, rest...)
}

func (d *dataLoader) getResultBufPair() (pair *BufPair) {
	d.mu.Lock()
	defer d.mu.Unlock()

	pair = d.resourceProvider.bufPairPool.Get().(*BufPair)
	d.inUseBufPair = append(d.inUseBufPair, pair)

	return
}

type fetchState interface {
	data() [][]byte
	next(ctx *Context) (*BufPair, error)
}

type batchFetchState struct {
	nextIdx int

	fetchError error
	results    []*BufPair
}

func (b *batchFetchState) data() [][]byte {
	dataSlice := make([][]byte, len(b.results))

	for i := range b.results {
		if b.results[i] != nil && b.results[i].HasData() {
			dataSlice[i] = b.results[i].Data.Bytes()
		}
	}

	return dataSlice
}

// next works correctly only with synchronous resolve strategy
// In case of asynchronous resolve strategy it's required to compute response position based on values from ctx (current path)
// But there is no reason for asynchronous resolve strategy, it's not useful, as all IO operations (fetching data) is be done by dataloader
func (b *batchFetchState) next(ctx *Context) (*BufPair, error) {
	if b.fetchError != nil {
		return nil, b.fetchError
	}

	res := b.results[b.nextIdx]

	b.nextIdx++

	return res, nil
}

type singleFetchState struct {
	nextIdx int

	fetchErrors []error
	results     []*BufPair
}

func (b *singleFetchState) data() [][]byte {
	dataSlice := make([][]byte, len(b.results))

	for i := range b.results {
		if b.results[i] != nil && b.results[i].HasData() {
			dataSlice[i] = b.results[i].Data.Bytes()
		}
	}

	return dataSlice
}

// next works correctly only with synchronous resolve strategy
// In case of asynchronous resolve strategy it's required to compute response position based on values from ctx (current path)
// But there is no reason for asynchronous resolve strategy, it's not useful, as all IO operations (fetching data) is be done by dataloader
func (b *singleFetchState) next(ctx *Context) (*BufPair, error) {
	if b.fetchErrors[b.nextIdx] != nil {
		return nil, b.fetchErrors[b.nextIdx]
	}

	res := b.results[b.nextIdx]

	b.nextIdx++

	return res, nil
}

func flatMap(input [][]byte, f func(val []byte) ([][]byte, error)) ([][]byte, error) {
	var result [][]byte

	for i := range input {
		mapRes, err := f(input[i])
		if err != nil {
			return nil, err
		}

		result = append(result, mapRes...)
	}

	return result, nil
}

func copyBufPair(to, from *BufPair) {
	if to == nil || from == nil {
		return
	}

	to.Data.WriteBytes(from.Data.Bytes())
	to.Errors.WriteBytes(from.Errors.Bytes())
}
