package enrich

import (
	"strings"
	"testing"
)

// URLs loaded by the captures of jjspy.com.
const (
	jjspyUA      = "https://www.google-analytics.com/j/collect?v=1&_v=j101&a=1491339337&t=pageview&_s=1&dl=https%3A%2F%2Fjjspy.com%2F&ul=en-us&de=UTF-8&dt=JJSpy&sd=24-bit&sr=1280x720&vp=1280x720&je=0&_u=IEBAAEABAAAAACAAI~&jid=1044578064&gjid=1925640716&cid=1457049316.1763015421&tid=UA-132944514-1&_gid=1311306311.1763015421&_r=1&gtm=45He4b70v9101&z=1630245745"
	jjspyAdsList = "https://www.google.com/pagead/1p-user-list/11021906314/?random=1763015421447&cv=11&fst=1763013600000&bg=ffffff&guid=ON&async=1&gtm=45be4b70v9101&u_w=1280&u_h=720&url=https%3A%2F%2Fjjspy.com%2F&tiba=JJSpy&fmt=3&is_vtc=1&cid=CAQSKQB7FLtq&random=2591467193&rmt_tld=0&ipr=y"
)

func trackerIDs(ts []Tracker) string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Kind+" "+t.ID)
	}
	return strings.Join(out, ", ")
}

func TestTrackerRules(t *testing.T) {
	for _, tt := range []struct{ desc, url, want string }{
		{"UA collect (jjspy)", jjspyUA, "ua UA-132944514-1"},
		{"UA collect", "https://www.google-analytics.com/collect?v=1&tid=UA-1234-5&t=pageview", "ua UA-1234-5"},
		{"UA gtag", "https://www.googletagmanager.com/gtag/js?id=UA-132944514-1", "ua UA-132944514-1"},
		{"GA4 collect", "https://region1.google-analytics.com/g/collect?v=2&tid=G-8ZK3QW1ABC&gtm=45je4b70v9101&_p=1&cid=1.2&en=page_view", "ga4 G-8ZK3QW1ABC"},
		{"GA4 gtag", "https://www.googletagmanager.com/gtag/js?id=G-8ZK3QW1ABC&l=dataLayer&cx=c", "ga4 G-8ZK3QW1ABC"},
		{"GA4 destination", "https://www.googletagmanager.com/gtag/destination?id=G-8ZK3QW1ABC&l=dataLayer&cx=c", "ga4 G-8ZK3QW1ABC"},
		{"GTM", "https://www.googletagmanager.com/gtm.js?id=GTM-5XQ7K2M", "gtm GTM-5XQ7K2M"},
		{"Google Ads user list (jjspy)", jjspyAdsList, "gads AW-11021906314"},
		{"Google Ads destination", "https://www.googletagmanager.com/gtag/destination?id=AW-11021906314&l=dataLayer&cx=c", "gads AW-11021906314"},
		{"Google Ads gtag", "https://www.googletagmanager.com/gtag/js?id=AW-11021906314", "gads AW-11021906314"},
		{"Google Ads conversion", "https://googleads.g.doubleclick.net/pagead/conversion/11021906314/?random=1&cv=11&fst=1&num=1", "gads AW-11021906314"},
		{"Google Ads view-through", "https://googleads.g.doubleclick.net/pagead/viewthroughconversion/11021906314/?random=1&cv=11", "gads AW-11021906314"},
		{"Google Ads services", "https://www.googleadservices.com/pagead/conversion/11021906314/?label=abc", "gads AW-11021906314"},
		{"Facebook config", "https://connect.facebook.net/signals/config/1234567890123456?v=2.9.177&r=stable", "fbpixel 1234567890123456"},
		{"Facebook tr", "https://www.facebook.com/tr/?id=1234567890123456&ev=PageView&dl=https%3A%2F%2Fx.example%2F&noscript=1", "fbpixel 1234567890123456"},
		{"Bing UET", "https://bat.bing.com/p/action/187051234.js", "bing_uet 187051234"},
		{"Clarity", "https://www.clarity.ms/tag/k4x9q2p7zm", "clarity k4x9q2p7zm"},
		{"Crazy Egg", "https://script.crazyegg.com/pages/scripts/0011/7426.js?492817", "crazyegg 00117426"},
		{"Crazy Egg versioned", "https://script.crazyegg.com/pages/versioned/tracking-scripts/0011/7426.js", "crazyegg 00117426"},
		{"Hotjar script", "https://static.hotjar.com/c/hotjar-3456789.js?sv=6", "hotjar 3456789"},
		{"Hotjar hjid", "https://vars.hotjar.com/box-0123.html?hjid=3456789", "hotjar 3456789"},
		{"Yandex", "https://mc.yandex.ru/watch/98765432?wmode=7&page-url=https%3A%2F%2Fx.example%2F", "yandex 98765432"},
		{"Paddle vendor", "https://checkout.paddle.com/api/1.0/checkout?vendor=123456&product=7", "payment paddle:123456"},
		{"Paddle script", "https://cdn.paddle.com/paddle/v2/paddle.js", "payment paddle"},
		{"Paddle self-hosted", "https://x.example/js/paddle.js", "payment paddle"},
		{"Stripe key", "https://api.stripe.com/v1/elements/sessions?key=pk_live_51HxYzAbCdEf012345&type=deferred_intent", "payment stripe:pk_live_51HxYzAbCdEf012345"},
		{"Stripe checkout", "https://checkout.stripe.com/c/pay/cs_live_a1b2c3", "payment stripe"},
		{"FastSpring storefront", "https://acme.onfastspring.com/popup-acme/session", "payment fastspring:acme"},
		{"FastSpring test storefront", "https://acme.test.onfastspring.com/popup-acme/session", "payment fastspring:acme"},
		{"FastSpring builder", "https://sbl.onfastspring.com/sbl/0.9.5/fastspring-builder.min.js", "payment fastspring"},
		{"2Checkout", "https://secure.2checkout.com/checkout/buy?merchant=ACME123&tpl=default", "payment 2checkout:ACME123"},
		{"Avangate", "https://secure.avangate.com/order/checkout.php?MERCHANT=ACME123", "payment 2checkout:ACME123"},
		{"PayPal client id", "https://www.paypal.com/sdk/js?client-id=AbC-123_xyz&currency=USD", "payment paypal:AbC-123_xyz"},
		{"PayPal sandbox", "https://www.paypal.com/sdk/js?client-id=sb", "payment paypal"},
	} {
		if got := trackerIDs(Trackers([]string{tt.url})); got != tt.want {
			t.Errorf("%s: %q, want %q", tt.desc, got, tt.want)
		}
	}
}

func TestTrackersNoFalsePositive(t *testing.T) {
	for _, u := range []string{
		"https://x.example/collect?tid=UA-132944514-1",
		"https://x.example/j/collect?tid=UA-132944514-1",
		"https://cdn.x.example/UA-132944514-1.js",
		"https://x.example/page?id=G-8ZK3QW1ABC",
		"https://x.example/g/collect?tid=UA-132944514-1",
		"https://www.google-analytics.com/analytics.js?tid=G-8ZK3QW1ABC",
		"https://www.google-analytics.com/collect?tid=G-8ZK3QW1ABC",
		"https://www.googletagmanager.com/gtag/js?id=GTM-5XQ7K2M",
		"https://notgoogletagmanager.com/gtm.js?id=GTM-5XQ7K2M",
		"https://x.example/gtm.js?id=GTM-5XQ7K2M",
		"https://x.example/pagead/conversion/11021906314/",
		"https://x.example/signals/config/1234567890123456",
		"https://x.example/tr?id=1234567890123456",
		"https://region1.google-analytics.com/g/collect?v=2&gtm=45je4b70v9101",
		"https://www.google-analytics.com/j/collect?tid=UA-abc",
		"not a url",
	} {
		if got := Trackers([]string{u}); len(got) != 0 {
			t.Errorf("%s: %s, want nothing", u, trackerIDs(got))
		}
	}
	for _, tt := range []struct{ url, unwanted string }{
		{jjspyUA, "gtm"},
		{jjspyAdsList, "gtm"},
	} {
		if got := trackerIDs(Trackers([]string{tt.url})); strings.Contains(got, tt.unwanted+" ") {
			t.Errorf("%s: %s, the gtm= parameter was decoded", tt.url, got)
		}
	}
}

func TestTrackersUnique(t *testing.T) {
	got := Trackers([]string{
		jjspyUA, jjspyAdsList, jjspyUA,
		"https://googleads.g.doubleclick.net/pagead/viewthroughconversion/11021906314/?random=2",
		"https://connect.facebook.net/signals/config/1234567890123456?v=2.9.177",
		"https://www.facebook.com/tr/?id=1234567890123456&ev=PageView",
		"https://cdn.paddle.com/paddle/v2/paddle.js",
		"https://checkout.paddle.com/api/1.0/checkout?vendor=123456",
		"https://js.stripe.com/v3/",
	})
	want := "fbpixel 1234567890123456, gads AW-11021906314, payment paddle:123456, payment stripe, ua UA-132944514-1"
	if s := trackerIDs(got); s != want {
		t.Errorf("trackers %s\nwant     %s", s, want)
	}
	if got := Trackers(nil); got == nil || len(got) != 0 {
		t.Errorf("no URL: %#v, want an empty list", got)
	}
}
