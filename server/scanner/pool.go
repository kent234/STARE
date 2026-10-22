package scanner

import (
	"context"
	"sync"
)

func runPool[T any, R any](
	ctx context.Context,
	workers int,
	jobs <-chan T,
	results chan<- R,
	process func(context.Context, T) (R, bool),
) {
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}
					if res, keep := process(ctx, job); keep {
						select {
						case results <- res:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()
}
