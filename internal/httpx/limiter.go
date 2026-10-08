package httpx

import (
	"context"
	"time"
)

// Limiter caps the global request rate. It is a plain ticker-fed token bucket
// rather than a dependency, so that the tool keeps a zero third-party
// footprint: a security scanner is a bad place to inherit someone else's
// supply chain.
type Limiter struct {
	tokens chan struct{}
	stop   chan struct{}
}

// NewLimiter returns a limiter permitting perSecond requests per second, with a
// small burst. A rate of zero or less returns nil, meaning unlimited.
func NewLimiter(perSecond float64) *Limiter {
	if perSecond <= 0 {
		return nil
	}
	burst := int(perSecond)
	if burst < 1 {
		burst = 1
	}
	if burst > 64 {
		burst = 64
	}
	l := &Limiter{
		tokens: make(chan struct{}, burst),
		stop:   make(chan struct{}),
	}
	interval := time.Duration(float64(time.Second) / perSecond)
	if interval <= 0 {
		interval = time.Microsecond
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-t.C:
				select {
				case l.tokens <- struct{}{}:
				default: // bucket full
				}
			}
		}
	}()
	return l
}

// Wait blocks until a token is available or the context ends.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.tokens:
		return nil
	}
}

// Close stops the refill goroutine.
func (l *Limiter) Close() {
	if l == nil {
		return
	}
	close(l.stop)
}
