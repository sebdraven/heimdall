package pg

import (
	"fmt"
	"net/netip"
	"testing"
)

func prefixes(vs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(vs))
	for _, v := range vs {
		out = append(out, netip.MustParsePrefix(v))
	}
	return out
}

func TestPlanCDNSync(t *testing.T) {
	held := []cdnHeld{
		{netip.MustParsePrefix("192.0.2.0/24"), "sync:fastly"},
		{netip.MustParsePrefix("198.51.100.0/24"), "sync:fastly"},
		{netip.MustParsePrefix("203.0.113.0/24"), "manual"},
		{netip.MustParsePrefix("2001:db8::/32"), "seed"},
		{netip.MustParsePrefix("2001:db8:1::/48"), "import:fastly.txt"},
		{netip.MustParsePrefix("10.0.0.0/8"), "sync:cloudfront"},
	}
	want := prefixes("192.0.2.0/24", "203.0.113.0/24", "2001:db8::/32", "10.0.0.0/8", "100.64.0.0/10", "2001:db8:2::/48")
	add, remove, res := planCDNSync("sync:fastly", want, held)
	if got := fmt.Sprint(add); got != "[100.64.0.0/10 2001:db8:2::/48]" {
		t.Errorf("add = %s", got)
	}
	// Only the sync:fastly row no longer listed goes; manual, seed, import
	// and another provider's sync are never removed.
	if got := fmt.Sprint(remove); got != "[198.51.100.0/24]" {
		t.Errorf("remove = %s", got)
	}
	if res != (CDNSync{Added: 2, Removed: 1, Unchanged: 1, Skipped: 3}) {
		t.Errorf("result = %+v", res)
	}

	add, remove, res = planCDNSync("sync:fastly", prefixes("192.0.2.0/24", "198.51.100.0/24"), held)
	if len(add) != 0 || len(remove) != 0 || res != (CDNSync{Unchanged: 2}) {
		t.Errorf("same list: add %v remove %v %+v", add, remove, res)
	}
}
