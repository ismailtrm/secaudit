package checker

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// bannerVersion extracts "product/version" pairs (e.g. nginx/1.18.0, PHP/7.4.3)
// from Server / X-Powered-By style values.
var bannerVersion = regexp.MustCompile(`([A-Za-z][A-Za-z0-9._+-]*)/(\d+(?:\.\d+)+)`)

// parenSegment matches parenthesized banner comments such as "(Ubuntu)".
var parenSegment = regexp.MustCompile(`\([^)]*\)`)

func bannerMatches(h http.Header, name string) [][]string {
	return bannerVersion.FindAllStringSubmatch(parenSegment.ReplaceAllString(h.Get(name), " "), -1)
}

// cookieTech maps a lowercased cookie-name substring to the technology it implies.
var cookieTech = map[string]string{
	"phpsessid":         "PHP",
	"jsessionid":        "Java (JSP/Servlet)",
	"asp.net_sessionid": "ASP.NET",
	".aspnetcore":       "ASP.NET Core",
	".aspxauth":         "ASP.NET",
	"laravel_session":   "Laravel",
	"ci_session":        "CodeIgniter",
	"csrftoken":         "Django",
	"wordpress_":        "WordPress",
	"wp-settings":       "WordPress",
	"connect.sid":       "Express (Node.js)",
	"_rails":            "Ruby on Rails",
}

// headerTech maps a header name to a technology its mere presence implies.
var headerTech = map[string]string{
	"X-Aspnet-Version":       "ASP.NET",
	"X-Aspnetmvc-Version":    "ASP.NET MVC",
	"X-Drupal-Cache":         "Drupal",
	"X-Drupal-Dynamic-Cache": "Drupal",
	"X-Pingback":             "WordPress",
	"X-Shopify-Stage":        "Shopify",
}

// fingerprint inspects response headers and cookies and returns the detected
// technologies (sorted, de-duplicated) and the product/version pairs disclosed
// in the Server / X-Powered-By headers.
func fingerprint(h http.Header, cookies []*http.Cookie) (tech []string, versions []string) {
	techSet := map[string]string{} // lowercased key -> display form
	addTech := func(t string) {
		k := strings.ToLower(t)
		if cur, ok := techSet[k]; !ok || t < cur {
			techSet[k] = t
		}
	}
	verSet := map[string]bool{}

	for _, name := range []string{"Server", "X-Powered-By"} {
		for _, m := range bannerMatches(h, name) {
			addTech(m[1])
			verSet[m[1]+"/"+m[2]] = true
		}
	}
	for name, t := range headerTech {
		if h.Get(name) != "" {
			addTech(t)
		}
	}
	if g := strings.TrimSpace(h.Get("X-Generator")); g != "" {
		addTech(g)
	}
	for _, c := range cookies {
		lower := strings.ToLower(c.Name)
		for sub, t := range cookieTech {
			if strings.Contains(lower, sub) {
				addTech(t)
			}
		}
	}

	tech = make([]string, 0, len(techSet))
	for _, k := range techSet {
		tech = append(tech, k)
	}
	versions = make([]string, 0, len(verSet))
	for k := range verSet {
		versions = append(versions, k)
	}
	sort.Strings(tech)
	sort.Strings(versions)
	return tech, versions
}

// bannerProducts returns the lowercased product and version of every
// product/version pair disclosed in the Server / X-Powered-By headers.
func bannerProducts(h http.Header) []struct{ Product, Version string } {
	var out []struct{ Product, Version string }
	for _, name := range []string{"Server", "X-Powered-By"} {
		for _, m := range bannerMatches(h, name) {
			out = append(out, struct{ Product, Version string }{strings.ToLower(m[1]), m[2]})
		}
	}
	return out
}
