package funcs

import (
	"math/rand"
	"time"
)

// RandomDuration picks a random duration somewhere between min and max.
// If you pass a bad range (min >= max), it just returns min and moves on.
// Kept separate from the sleep call so it can be tested without actually waiting.
func RandomDuration(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}
	delta := max - min
	return min + time.Duration(rand.Int63n(int64(delta)))
}

// SleepWithJitter blocks for a random amount of time between min and max.
// It calls RandomDuration to pick the value, then hands it off to time.Sleep.
func SleepWithJitter(min, max time.Duration) {
	time.Sleep(RandomDuration(min, max))
}
