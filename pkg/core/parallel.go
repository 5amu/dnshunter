package core

import "sync"

// ParallelMap applies fn to every item using at most limit goroutines and
// returns the results in the same order as items.
func ParallelMap[T, R any](items []T, limit int, fn func(T) R) []R {
	out := make([]R, len(items))
	if limit <= 0 {
		limit = 1
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, it T) {
			defer func() { <-sem; wg.Done() }()
			out[i] = fn(it)
		}(i, it)
	}
	wg.Wait()
	return out
}
