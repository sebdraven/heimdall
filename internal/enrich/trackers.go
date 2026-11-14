package enrich

import (
	"cmp"
	"maps"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Kinds of tracker and payment identifiers.
const (
	TrackerUA       = "ua"
	TrackerGA4      = "ga4"
	TrackerGTM      = "gtm"
	TrackerGAds     = "gads"
	TrackerFBPixel  = "fbpixel"
	TrackerBingUET  = "bing_uet"
	TrackerPayment  = "payment"
	TrackerClarity  = "clarity"
	TrackerCrazyEgg = "crazyegg"
	TrackerHotjar   = "hotjar"
	TrackerYandex   = "yandex"
)

// Tracker is an identifier found in a loaded URL. A payment is
// "<provider>" or "<provider>:<merchant id>".
type Tracker struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

var (
	reUA          = regexp.MustCompile(`^UA-\d+-\d+$`)
	reGA4         = regexp.MustCompile(`^G-[A-Z0-9]+$`)
	reGTM         = regexp.MustCompile(`^GTM-[A-Z0-9]+$`)
	reAW          = regexp.MustCompile(`^AW-\d+$`)
	reDigits      = regexp.MustCompile(`^\d+$`)
	reToken       = regexp.MustCompile(`^[0-9A-Za-z_-]+$`)
	reStripeKey   = regexp.MustCompile(`^pk_live_[0-9A-Za-z]+$`)
	reGACollect   = regexp.MustCompile(`^/(j/)?collect$`)
	reAdsPath     = regexp.MustCompile(`^/pagead/(?:1p-user-list|conversion|viewthroughconversion)/(\d+)(?:/|$)`)
	reFBConfig    = regexp.MustCompile(`^/signals/config/(\d+)$`)
	reBingAction  = regexp.MustCompile(`^/p/action/(\d+)(?:\.js)?$`)
	reClarityTag  = regexp.MustCompile(`^/tag/([0-9A-Za-z]+)$`)
	reCrazyEgg    = regexp.MustCompile(`^/pages/(?:versioned/tracking-scripts|scripts)/((?:\d+/)*\d+)(?:\.js)?(?:/|$)`)
	reHotjarPath  = regexp.MustCompile(`^/c/hotjar-(\d+)\.js$`)
	reYandexWatch = regexp.MustCompile(`^/watch/(\d+)(?:/|$)`)
)

// trackerRule finds the identifiers of one kind in a URL.
type trackerRule struct {
	kind string
	ids  func(u *url.URL) []string
}

var trackerRules = []trackerRule{
	{TrackerUA, func(u *url.URL) []string {
		switch {
		case onHost(u, "google-analytics.com") && reGACollect.MatchString(u.Path):
			return param(u, "tid", reUA)
		case onHost(u, "googletagmanager.com") && u.Path == "/gtag/js":
			return param(u, "id", reUA)
		}
		return nil
	}},
	{TrackerGA4, func(u *url.URL) []string {
		switch {
		case strings.HasSuffix(u.Path, "/g/collect"):
			return param(u, "tid", reGA4)
		case onHost(u, "googletagmanager.com") && (u.Path == "/gtag/js" || u.Path == "/gtag/destination"):
			return param(u, "id", reGA4)
		}
		return nil
	}},
	{TrackerGTM, func(u *url.URL) []string {
		if onHost(u, "googletagmanager.com") && u.Path == "/gtm.js" {
			return param(u, "id", reGTM)
		}
		return nil
	}},
	{TrackerGAds, func(u *url.URL) []string {
		switch {
		case onHost(u, "googletagmanager.com") && (u.Path == "/gtag/js" || u.Path == "/gtag/destination"):
			return param(u, "id", reAW)
		case onHost(u, "doubleclick.net", "googleadservices.com") || onGoogle(u):
			if m := reAdsPath.FindStringSubmatch(u.Path); m != nil {
				return []string{"AW-" + m[1]}
			}
		}
		return nil
	}},
	{TrackerFBPixel, func(u *url.URL) []string {
		switch {
		case onHost(u, "connect.facebook.net"):
			return pathID(u, reFBConfig)
		case onHost(u, "facebook.com") && strings.TrimSuffix(u.Path, "/") == "/tr":
			return param(u, "id", reDigits)
		}
		return nil
	}},
	{TrackerBingUET, func(u *url.URL) []string {
		if onHost(u, "bat.bing.com") {
			return pathID(u, reBingAction)
		}
		return nil
	}},
	{TrackerPayment, payment},
	{TrackerClarity, func(u *url.URL) []string {
		if onHost(u, "clarity.ms") {
			return pathID(u, reClarityTag)
		}
		return nil
	}},
	{TrackerCrazyEgg, func(u *url.URL) []string {
		if onHost(u, "script.crazyegg.com") {
			if m := reCrazyEgg.FindStringSubmatch(u.Path); m != nil {
				return []string{strings.ReplaceAll(m[1], "/", "")}
			}
		}
		return nil
	}},
	{TrackerHotjar, func(u *url.URL) []string {
		if !onHost(u, "hotjar.com") {
			return nil
		}
		return append(param(u, "hjid", reDigits), pathID(u, reHotjarPath)...)
	}},
	{TrackerYandex, func(u *url.URL) []string {
		if onHost(u, "mc.yandex.ru", "mc.yandex.com") {
			return pathID(u, reYandexWatch)
		}
		return nil
	}},
}

// paymentProviders are the hosts of the checkout scripts and pages; merchant
// reads the merchant id a URL carries, "" if none.
var paymentProviders = []struct {
	name     string
	match    func(u *url.URL) bool
	merchant func(u *url.URL) string
}{
	{"paddle", func(u *url.URL) bool { return onHost(u, "paddle.com") || path.Base(u.Path) == "paddle.js" },
		func(u *url.URL) string { return firstParam(u, reDigits, "vendor", "vendor_id", "seller", "seller_id") }},
	{"stripe", func(u *url.URL) bool { return onHost(u, "stripe.com") },
		func(u *url.URL) string { return anyParam(u, reStripeKey) }},
	{"fastspring", func(u *url.URL) bool { return onHost(u, "fastspring.com", "onfastspring.com") },
		storefront},
	{"2checkout", func(u *url.URL) bool { return onHost(u, "2checkout.com", "avangate.com") },
		func(u *url.URL) string { return foldParam(u, reToken, "merchant") }},
	{"paypal", func(u *url.URL) bool { return onHost(u, "paypal.com") && strings.HasPrefix(u.Path, "/sdk/") },
		func(u *url.URL) string {
			if id := firstParam(u, reToken, "client-id"); id != "sb" {
				return id
			}
			return ""
		}},
}

func payment(u *url.URL) []string {
	for _, p := range paymentProviders {
		if !p.match(u) {
			continue
		}
		if m := p.merchant(u); m != "" {
			return []string{p.name + ":" + m}
		}
		return []string{p.name}
	}
	return nil
}

// fastspringHosts are the FastSpring hosts that are not a storefront.
var fastspringHosts = []string{"sbl", "www", "api", "app", "cdn", "static", "sites"}

// storefront reads the FastSpring storefront of <store>.onfastspring.com,
// <store>.test.onfastspring.com or sites.fastspring.com/<store>/.
func storefront(u *url.URL) string {
	h := hostOf(u)
	if h == "sites.fastspring.com" {
		first, _, _ := strings.Cut(strings.TrimPrefix(u.Path, "/"), "/")
		if reToken.MatchString(first) {
			return first
		}
		return ""
	}
	store, ok := strings.CutSuffix(h, ".onfastspring.com")
	if !ok {
		return ""
	}
	store = strings.TrimSuffix(store, ".test")
	if strings.Contains(store, ".") || slices.Contains(fastspringHosts, store) || !reToken.MatchString(store) {
		return ""
	}
	return store
}

// Trackers returns the identifiers found in urls, sorted and unique. A
// payment provider without merchant id is left out when a URL names one.
func Trackers(urls []string) []Tracker {
	seen := map[Tracker]bool{}
	for _, raw := range urls {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" {
			continue
		}
		for _, r := range trackerRules {
			for _, id := range r.ids(u) {
				seen[Tracker{Kind: r.kind, ID: id}] = true
			}
		}
	}
	out := []Tracker{}
	for t := range seen {
		if t.Kind == TrackerPayment && !strings.Contains(t.ID, ":") && hasMerchant(seen, t.ID) {
			continue
		}
		out = append(out, t)
	}
	slices.SortFunc(out, compareTracker)
	return out
}

func hasMerchant(seen map[Tracker]bool, provider string) bool {
	for t := range seen {
		if t.Kind == TrackerPayment && strings.HasPrefix(t.ID, provider+":") {
			return true
		}
	}
	return false
}

func compareTracker(a, b Tracker) int {
	return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.ID, b.ID))
}

func hostOf(u *url.URL) string {
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}

// onHost reports whether the host of u is one of domains or below it.
func onHost(u *url.URL, domains ...string) bool {
	h := hostOf(u)
	for _, d := range domains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// onGoogle reports whether the registrable domain of u is google.<suffix>.
func onGoogle(u *url.URL) bool {
	reg, err := publicsuffix.EffectiveTLDPlusOne(hostOf(u))
	return err == nil && strings.HasPrefix(reg, "google.")
}

func param(u *url.URL, name string, re *regexp.Regexp) []string {
	if v := u.Query().Get(name); re.MatchString(v) {
		return []string{v}
	}
	return nil
}

func pathID(u *url.URL, re *regexp.Regexp) []string {
	if m := re.FindStringSubmatch(u.Path); m != nil {
		return []string{m[1]}
	}
	return nil
}

func firstParam(u *url.URL, re *regexp.Regexp, names ...string) string {
	q := u.Query()
	for _, n := range names {
		if v := q.Get(n); re.MatchString(v) {
			return v
		}
	}
	return ""
}

// foldParam is firstParam with a name of any case.
func foldParam(u *url.URL, re *regexp.Regexp, name string) string {
	q := u.Query()
	for _, k := range slices.Sorted(maps.Keys(q)) {
		if strings.EqualFold(k, name) && re.MatchString(q.Get(k)) {
			return q.Get(k)
		}
	}
	return ""
}

func anyParam(u *url.URL, re *regexp.Regexp) string {
	q := u.Query()
	for _, k := range slices.Sorted(maps.Keys(q)) {
		for _, v := range q[k] {
			if re.MatchString(v) {
				return v
			}
		}
	}
	return ""
}
