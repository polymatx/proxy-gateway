package proxy

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func newTestHealth() *Health {
	lg := logrus.New()
	lg.SetLevel(logrus.PanicLevel)
	return NewHealth(HealthConfig{FailThreshold: 3, RiseThreshold: 2}, lg)
}

// A provider nobody has tried yet must be usable, or every deployment would
// start by refusing traffic to everything.
func TestUnknownProviderIsHealthy(t *testing.T) {
	if !newTestHealth().IsHealthy("never-seen") {
		t.Fatal("an unknown provider should be assumed healthy")
	}
}

// One or two failures are the upstream being flaky, which the gateway already
// retries through. Only a sustained run should take a provider out.
func TestProviderSurvivesIsolatedFailures(t *testing.T) {
	h := newTestHealth()
	for i := 0; i < 10; i++ {
		h.RecordFailure("p")
		h.RecordFailure("p")
		h.RecordSuccess("p") // a success in between resets the run
		if !h.IsHealthy("p") {
			t.Fatalf("marked unhealthy after %d intermittent failures", i)
		}
	}
}

func TestProviderGoesDownAfterConsecutiveFailures(t *testing.T) {
	h := newTestHealth()
	h.RecordFailure("p")
	h.RecordFailure("p")
	if !h.IsHealthy("p") {
		t.Fatal("went down one failure early")
	}
	h.RecordFailure("p")
	if h.IsHealthy("p") {
		t.Fatal("should be unhealthy after 3 consecutive failures")
	}
}

// Coming back needs more than a single lucky request.
func TestRecoveryNeedsConsecutiveSuccesses(t *testing.T) {
	h := newTestHealth()
	for i := 0; i < 3; i++ {
		h.RecordFailure("p")
	}
	h.RecordSuccess("p")
	if h.IsHealthy("p") {
		t.Fatal("recovered on a single success")
	}
	h.RecordSuccess("p")
	if !h.IsHealthy("p") {
		t.Fatal("should be healthy after 2 consecutive successes")
	}
}

// A failure during recovery restarts the count.
func TestFailureDuringRecoveryResets(t *testing.T) {
	h := newTestHealth()
	for i := 0; i < 3; i++ {
		h.RecordFailure("p")
	}
	h.RecordSuccess("p")
	h.RecordFailure("p")
	h.RecordSuccess("p")
	if h.IsHealthy("p") {
		t.Fatal("a failure mid-recovery should restart the rise count")
	}
}

func healthyPool(t *testing.T, h *Health, slugs ...string) *ProxyProvider {
	t.Helper()
	lg := logrus.New()
	lg.SetLevel(logrus.PanicLevel)
	p := &ProxyProvider{proxyMap: map[string]*ProxyData{}}
	for _, s := range slugs {
		p.proxies = append(p.proxies, ProxyData{Slug: s, IsGlobal: true})
	}
	p.SetHealth(h, lg)
	return p
}

// The point of the whole change: a provider that is down stops receiving
// traffic while its healthy sibling keeps serving.
func TestSelectionAvoidsUnhealthyProviders(t *testing.T) {
	h := newTestHealth()
	p := healthyPool(t, h, "good", "bad")
	for i := 0; i < 3; i++ {
		h.RecordFailure("bad")
	}

	for i := 0; i < 200; i++ {
		got := p.GetRandomGlobalProxy()
		if got == nil {
			t.Fatal("selection returned nothing while a healthy provider existed")
		}
		if got.Slug == "bad" {
			t.Fatal("selected a provider marked unhealthy")
		}
	}
}

// Health is an inference. If it says everything is down, the likelier
// explanation is that the inference is wrong -- serve traffic rather than
// guarantee an outage.
func TestSelectionFallsBackWhenEverythingIsUnhealthy(t *testing.T) {
	h := newTestHealth()
	p := healthyPool(t, h, "a", "b")
	for _, s := range []string{"a", "b"} {
		for i := 0; i < 3; i++ {
			h.RecordFailure(s)
		}
	}

	if got := p.GetRandomGlobalProxy(); got == nil {
		t.Fatal("refused all traffic instead of falling back")
	}
}

func TestSnapshotReportsState(t *testing.T) {
	h := newTestHealth()
	h.RecordSuccess("up")
	for i := 0; i < 3; i++ {
		h.RecordFailure("down")
	}
	snap := h.Snapshot()
	if !snap["up"] || snap["down"] {
		t.Fatalf("snapshot wrong: %v", snap)
	}
}
