package server

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// v0.4.27: a context canceled inside a worker run (provider stream cancel etc.) is not a
// terminal failure — it backs off and retries like model_error; task-level cancellation
// is not (handled by the existing branch).
func TestIsTransientContextCanceled(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"wrapped canceled", fmt.Errorf("stream: %w", context.Canceled), true},
		{"text match", errors.New("error: context canceled"), true},
		{"other", errors.New("connection reset by peer"), false},
		{"deadline is not cancel", fmt.Errorf("run: %w", context.DeadlineExceeded), false},
	}
	for _, c := range cases {
		if got := isTransientContextCanceled(c.err); got != c.want {
			t.Fatalf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
