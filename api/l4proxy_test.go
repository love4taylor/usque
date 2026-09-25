package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

type blockingL4ClientConn struct{}

func (blockingL4ClientConn) OpenRequestStream(ctx context.Context) (*http3.RequestStream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestL4OpenStreamTimeoutEvictsSharedConnection(t *testing.T) {
	cached := &l4HTTP3Client{clientConn: blockingL4ClientConn{}}
	proxy := &L4Proxy{client: cached}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := proxy.dial(ctx, "example.com:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial error = %v, want deadline exceeded", err)
	}
	if proxy.client != nil {
		t.Fatal("timed-out shared connection remained cached")
	}
}

func TestL4OpenStreamCancellationKeepsSharedConnection(t *testing.T) {
	cached := &l4HTTP3Client{clientConn: blockingL4ClientConn{}}
	proxy := &L4Proxy{client: cached}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := proxy.dial(ctx, "example.com:443")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("dial error = %v, want canceled", err)
	}
	if proxy.client != cached {
		t.Fatal("caller cancellation evicted shared connection")
	}
}

func TestL4ConnectWaitHonorsDeadline(t *testing.T) {
	proxy := &L4Proxy{connectSlot: make(chan struct{}, 1)}
	proxy.connectSlot <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := proxy.getOrCreateClientConn(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("connection wait error = %v, want deadline exceeded", err)
	}
}
