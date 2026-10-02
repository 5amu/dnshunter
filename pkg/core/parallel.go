package core

import (
	"fmt"
	"runtime/debug"
	"sync"
)

// ParallelMap applies fn to every item using at most limit goroutines and
// returns the results in the same order as items. A panic in fn is re-raised
// in the calling goroutine, so that the caller's recover (e.g. the scanner's)
// can handle it.
func ParallelMap[T, R any](items []T, limit int, fn func(T) R) []R {
	out := make([]R, len(items))
	if limit <= 0 {
		limit = 1
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	var once sync.Once
	var panicked any
	for i, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, it T) {
			defer func() {
				if p := recover(); p != nil {
					once.Do(func() { panicked = fmt.Sprintf("%v\n%s", p, debug.Stack()) })
				}
				<-sem
				wg.Done()
			}()
			out[i] = fn(it)
		}(i, it)
	}
	wg.Wait()
	if panicked != nil {
		panic(panicked)
	}
	return out
}
