package checker

import "testing"

func TestTakeoverService(t *testing.T) {
	tests := []struct {
		name    string
		cname   string
		wantSvc string
		wantOK  bool
	}{
		{"github pages", "user.github.io.", "GitHub Pages", true},
		{"s3 bucket", "my-bucket.s3.amazonaws.com", "AWS S3", true},
		{"s3 website endpoint", "my-bucket.s3-website-us-east-1.amazonaws.com", "AWS S3", true},
		{"heroku app", "myapp.herokuapp.com", "Heroku", true},
		{"heroku dns", "myapp.herokudns.com", "Heroku", true},
		{"azure websites", "myapp.azurewebsites.net", "Azure", true},
		{"azure cloudapp", "myapp.cloudapp.net", "Azure", true},
		{"azure traffic manager", "myapp.trafficmanager.net", "Azure", true},
		{"fastly", "cdn.fastly.net", "Fastly", true},
		{"shopify", "shop.myshopify.com", "Shopify", true},
		{"surge", "site.surge.sh", "Surge", true},
		{"zendesk", "help.zendesk.com", "Zendesk", true},
		{"readthedocs", "docs.readthedocs.io", "Read the Docs", true},
		{"tumblr", "blog.domains.tumblr.com", "Tumblr", true},
		{"case insensitive", "USER.GITHUB.IO", "GitHub Pages", true},
		{"mixed trailing dot and case", "My-Bucket.S3.Amazonaws.Com.", "AWS S3", true},
		{"unrelated host", "www.example.com", "", false},
		{"own infra cname", "app.internal-lb.example.com", "", false},
		{"empty cname", "", "", false},
		{"whitespace only", "   ", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, ok := takeoverService(tt.cname)
			if ok != tt.wantOK {
				t.Fatalf("takeoverService(%q) ok = %v, want %v", tt.cname, ok, tt.wantOK)
			}
			if svc != tt.wantSvc {
				t.Errorf("takeoverService(%q) svc = %q, want %q", tt.cname, svc, tt.wantSvc)
			}
		})
	}
}

func TestMatchesFingerprint(t *testing.T) {
	tests := []struct {
		name   string
		svc    string
		body   string
		status int
		want   bool
	}{
		{
			name:   "github pages unclaimed",
			svc:    "GitHub Pages",
			body:   "<html>There isn't a GitHub Pages site here.</html>",
			status: 404,
			want:   true,
		},
		{
			name:   "s3 no such bucket",
			svc:    "AWS S3",
			body:   "<Error><Code>NoSuchBucket</Code></Error>",
			status: 404,
			want:   true,
		},
		{
			name:   "heroku no such app",
			svc:    "Heroku",
			body:   "Heroku | No such app",
			status: 404,
			want:   true,
		},
		{
			name:   "fastly unknown domain",
			svc:    "Fastly",
			body:   "Fastly error: unknown domain example.com",
			status: 500,
			want:   true,
		},
		{
			name:   "shopify unavailable",
			svc:    "Shopify",
			body:   "Sorry, this shop is currently unavailable.",
			status: 404,
			want:   true,
		},
		{
			name:   "surge project not found",
			svc:    "Surge",
			body:   "project not found",
			status: 404,
			want:   true,
		},
		{
			name:   "case insensitive fingerprint match",
			svc:    "GitHub Pages",
			body:   "THERE ISN'T A GITHUB PAGES SITE HERE.",
			status: 404,
			want:   true,
		},
		{
			name:   "claimed github pages site",
			svc:    "GitHub Pages",
			body:   "<html><body><h1>Welcome to my real site</h1></body></html>",
			status: 200,
			want:   false,
		},
		{
			name:   "claimed s3 bucket serving content",
			svc:    "AWS S3",
			body:   "<html><body>my static site content</body></html>",
			status: 200,
			want:   false,
		},
		{
			name:   "unknown service",
			svc:    "Not A Real Service",
			body:   "There isn't a GitHub Pages site here.",
			status: 404,
			want:   false,
		},
		{
			name:   "empty body",
			svc:    "Heroku",
			body:   "",
			status: 404,
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesFingerprint(tt.svc, tt.body, tt.status)
			if got != tt.want {
				t.Errorf("matchesFingerprint(%q, ..., %d) = %v, want %v", tt.svc, tt.status, got, tt.want)
			}
		})
	}
}
