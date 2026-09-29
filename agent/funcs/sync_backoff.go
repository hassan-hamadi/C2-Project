package funcs

import (
	"math/rand"
	"time"
)

// CalculateBackoff returns a random duration in [min, max), or min for an
// invalid range.
func CalculateBackoff(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}
	delta := max - min
	return min + time.Duration(rand.Int63n(int64(delta)))
}

// DelayNextSync waits for a randomized interval.
func DelayNextSync(min, max time.Duration) {
	time.Sleep(CalculateBackoff(min, max))
}
