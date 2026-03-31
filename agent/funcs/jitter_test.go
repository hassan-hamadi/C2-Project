package funcs

import (
	"testing"
	"time"
)

// RandomDuration tests

// Checks that every value we get back actually lands between min and max.
// Runs 10,000 samples to be thorough.
func TestRandomDuration_InRange(t *testing.T) {
	min := 8 * time.Second
	max := 15 * time.Second
	const samples = 10_000

	for i := 0; i < samples; i++ {
		d := RandomDuration(min, max)
		if d < min || d >= max {
			t.Fatalf("sample %d out of range: got %v, want [%v, %v)", i, d, min, max)
		}
	}
}

// Makes sure the guard clause works when the range doesn't make sense.
// Equal bounds, inverted bounds, and zero max should all just return min.
func TestRandomDuration_DegenerateRange(t *testing.T) {
	cases := []struct {
		name     string
		min, max time.Duration
	}{
		{"equal", 10 * time.Second, 10 * time.Second},
		{"inverted", 15 * time.Second, 8 * time.Second},
		{"zero max", 5 * time.Second, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := RandomDuration(tc.min, tc.max)
			if d != tc.min {
				t.Errorf("degenerate range: got %v, want %v (min)", d, tc.min)
			}
		})
	}
}

// Checks that the function isn't just always returning the minimum.
// Over 100 draws, at least one should come back higher than min.
func TestRandomDuration_NotAlwaysMin(t *testing.T) {
	min := 8 * time.Second
	max := 15 * time.Second
	const samples = 100

	allMin := true
	for i := 0; i < samples; i++ {
		if RandomDuration(min, max) > min {
			allMin = false
			break
		}
	}
	if allMin {
		t.Errorf("all %d samples returned exactly min, something is wrong with the RNG", samples)
	}
}

// Same idea as above but for the top end. At least one sample should come
// back well below max, otherwise the distribution is clearly broken.
func TestRandomDuration_NotAlwaysMax(t *testing.T) {
	min := 8 * time.Second
	max := 15 * time.Second
	const samples = 100

	allMax := true
	for i := 0; i < samples; i++ {
		if RandomDuration(min, max) < max-time.Second {
			allMax = false
			break
		}
	}
	if allMax {
		t.Errorf("all %d samples were near max, distribution is skewed", samples)
	}
}

// Splits the range into buckets and takes a large number of samples to check
// that values are spread roughly evenly. Each bucket should get about 1/7 of
// the total. We allow up to 30% deviation to account for normal randomness.
func TestRandomDuration_Distribution(t *testing.T) {
	const (
		buckets   = 7
		samples   = 70_000
		tolerance = 0.30
	)

	min := 0 * time.Second
	max := time.Duration(buckets) * time.Second
	bucketWidth := (max - min) / buckets
	counts := make([]int, buckets)

	for i := 0; i < samples; i++ {
		d := RandomDuration(min, max)
		idx := int(d / bucketWidth)
		if idx >= buckets {
			idx = buckets - 1
		}
		counts[idx]++
	}

	expected := float64(samples) / float64(buckets)
	for i, count := range counts {
		ratio := float64(count) / expected
		if ratio < 1-tolerance || ratio > 1+tolerance {
			t.Errorf("bucket %d: got %d samples (%.2fx expected %.0f), distribution is skewed",
				i, count, ratio, expected)
		}
	}
}

// SleepWithJitter tests

// Makes sure SleepWithJitter actually sleeps and that the wait time lands
// within the range. Uses milliseconds so the test finishes fast.
func TestSleepWithJitter_Timing(t *testing.T) {
	min := 10 * time.Millisecond
	max := 50 * time.Millisecond

	start := time.Now()
	SleepWithJitter(min, max)
	elapsed := time.Since(start)

	// Give it 20ms of slack for OS scheduling variance.
	const overshoot = 20 * time.Millisecond
	if elapsed < min {
		t.Errorf("slept too short: %v < min %v", elapsed, min)
	}
	if elapsed > max+overshoot {
		t.Errorf("slept too long: %v > max %v (+%v overshoot)", elapsed, max, overshoot)
	}
}

// Makes sure passing equal bounds doesn't cause a panic.
// It should just sleep for the minimum and return cleanly.
func TestSleepWithJitter_DegenerateDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SleepWithJitter panicked on degenerate range: %v", r)
		}
	}()
	SleepWithJitter(5*time.Millisecond, 5*time.Millisecond)
}
