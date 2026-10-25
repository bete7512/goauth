// Package middlewares holds the rate-limit HTTP middleware.
package middlewares

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bete7512/goauth/internal/middleware"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

// Rule is a validated rate-limit rule.
type Rule struct {
	Name        string
	ApplyTo     []types.RouteName
	ExcludeFrom []types.RouteName
	Key         types.RateLimitKey
	Budget      types.RateLimitRule
}

// Options configures a Limiter.
type Options struct {
	Store          types.RateLimitStore
	Rules          []Rule
	TrustedProxies []net.IPNet
	Allowlist      []net.IPNet
	FailClosed     bool
	IPv6PrefixBits int
	Headers        bool
	MaxBodyBytes   int64
	Events         types.EventBus
	Logger         types.Logger
	Now            func() time.Time
}

// Limiter applies the configured rules to each request. Rules are matched by
// the route name that Auth places in the request context, so one global
// middleware serves every route.
type Limiter struct {
	opts       Options
	routeRules sync.Map // route name -> []*Rule
	lastWarn   atomic.Int64
}

const (
	keyPrefix          = "rl:"
	storeWarnInterval  = 60 // seconds
	defaultIPv6Prefix  = 64
	defaultMaxBodySize = 1 << 20
)

// New returns a Limiter for opts.
func New(opts Options) *Limiter {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.IPv6PrefixBits <= 0 {
		opts.IPv6PrefixBits = defaultIPv6Prefix
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = defaultMaxBodySize
	}
	return &Limiter{opts: opts}
}

// Middleware returns the HTTP middleware.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, _ := r.Context().Value(types.RouteNameKey).(string)
		rules := l.rulesFor(route)
		if len(rules) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		ip := http_utils.ClientIP(r, l.opts.TrustedProxies)
		if parsed := net.ParseIP(ip); parsed != nil && http_utils.IPInNets(parsed, l.opts.Allowlist) {
			next.ServeHTTP(w, r)
			return
		}
		bucket := http_utils.BucketIP(ip, l.opts.IPv6PrefixBits)
		now := l.opts.Now()

		var (
			identifier       string
			identifierLoaded bool
			tightest         *types.RateLimitDecision
		)
		for _, rule := range rules {
			key, keyHash := "", ""
			switch rule.Key {
			case types.RateLimitKeyIdentifier, types.RateLimitKeyIPIdentifier:
				if !identifierLoaded {
					identifier, r = l.identifier(r)
					identifierLoaded = true
				}
				if identifier == "" {
					continue
				}
				keyHash = hashIdentifier(rule.Name, identifier)
				if rule.Key == types.RateLimitKeyIdentifier {
					key = keyPrefix + rule.Name + ":id:" + keyHash
				} else {
					key = keyPrefix + rule.Name + ":ipid:" + bucket + ":" + keyHash
				}
			default:
				key = keyPrefix + rule.Name + ":ip:" + bucket
			}

			decision, err := l.opts.Store.Take(r.Context(), key, rule.Budget, now)
			if err != nil {
				l.storeFailure(rule, err)
				if l.opts.FailClosed {
					http_utils.RespondError(w, http.StatusServiceUnavailable, string(types.ErrInternalError), "Rate limiter unavailable")
					return
				}
				continue
			}
			if !decision.Allowed {
				l.reject(w, r, rule, decision, now, route, ip, keyHash)
				return
			}
			if tightest == nil || decision.Remaining < tightest.Remaining {
				d := decision
				tightest = &d
			}
		}
		if tightest != nil && l.opts.Headers {
			setBudgetHeaders(w.Header(), *tightest, now)
		}
		next.ServeHTTP(w, r)
	})
}

// rulesFor returns the rules matching route, cached per route name.
func (l *Limiter) rulesFor(route string) []*Rule {
	if cached, ok := l.routeRules.Load(route); ok {
		return cached.([]*Rule)
	}
	var matched []*Rule
	for i := range l.opts.Rules {
		rule := &l.opts.Rules[i]
		if matchesAny(rule.ApplyTo, route) && !matchesAny(rule.ExcludeFrom, route) {
			matched = append(matched, rule)
		}
	}
	l.routeRules.Store(route, matched)
	return matched
}

func matchesAny(patterns []types.RouteName, route string) bool {
	for _, pattern := range patterns {
		if middleware.MatchPattern(pattern, route) {
			return true
		}
	}
	return false
}

// identifier extracts a normalized email, username or phone number from a JSON
// body and returns the request with its body restored for the handler.
func (l *Limiter) identifier(r *http.Request) (string, *http.Request) {
	if r.Body == nil || r.Body == http.NoBody {
		return "", r
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return "", r
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.Contains(strings.ToLower(ct), "json") {
		return "", r
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, l.opts.MaxBodyBytes+1))
	r.Body = restoredBody{Reader: io.MultiReader(bytes.NewReader(buf), r.Body), Closer: r.Body}
	if err != nil || int64(len(buf)) > l.opts.MaxBodyBytes {
		return "", r
	}
	var body struct {
		Email       string `json:"email"`
		Username    string `json:"username"`
		Phone       string `json:"phone"`
		PhoneNumber string `json:"phone_number"`
	}
	if json.Unmarshal(buf, &body) != nil {
		return "", r
	}
	for _, candidate := range []string{body.Email, body.Username, body.Phone, body.PhoneNumber} {
		if value := strings.ToLower(strings.TrimSpace(candidate)); value != "" {
			return value, r
		}
	}
	return "", r
}

type restoredBody struct {
	io.Reader
	io.Closer
}

func (l *Limiter) reject(w http.ResponseWriter, r *http.Request, rule *Rule, decision types.RateLimitDecision, now time.Time, route, ip, keyHash string) {
	retry := ceilSeconds(decision.RetryAfter)
	if retry < 1 {
		retry = 1
	}
	header := w.Header()
	header.Set("Retry-After", strconv.FormatInt(retry, 10))
	if l.opts.Headers {
		setBudgetHeaders(header, decision, now)
	}
	l.emit(r.Context(), rule, route, ip, keyHash, retry, now)
	authErr := types.NewRateLimitExceededError(decision.RetryAfter)
	http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
}

func (l *Limiter) emit(ctx context.Context, rule *Rule, route, ip, keyHash string, retry int64, now time.Time) {
	if l.opts.Events == nil {
		return
	}
	data := &types.RateLimitExceededData{
		Route:             route,
		Rule:              rule.Name,
		Key:               rule.Key,
		KeyHash:           keyHash,
		IPAddress:         ip,
		RetryAfterSeconds: retry,
		Details:           fmt.Sprintf("Rate limit %q exceeded on %s", rule.Name, route),
		Timestamp:         now,
	}
	if err := l.opts.Events.EmitAsync(ctx, types.EventRateLimitExceeded, data); err != nil && l.opts.Logger != nil {
		l.opts.Logger.Warn("rate limit event not emitted", "rule", rule.Name, "error", err)
	}
}

// storeFailure logs a store error at most once per minute.
func (l *Limiter) storeFailure(rule *Rule, err error) {
	if l.opts.Logger == nil {
		return
	}
	now := time.Now().Unix()
	last := l.lastWarn.Load()
	if now-last < storeWarnInterval || !l.lastWarn.CompareAndSwap(last, now) {
		return
	}
	outcome := "allowing requests"
	if l.opts.FailClosed {
		outcome = "rejecting requests"
	}
	l.opts.Logger.Warn("rate limit store failed; "+outcome, "rule", rule.Name, "error", err)
}

func setBudgetHeaders(header http.Header, decision types.RateLimitDecision, now time.Time) {
	header.Set("RateLimit-Limit", strconv.Itoa(decision.Limit))
	header.Set("RateLimit-Remaining", strconv.Itoa(decision.Remaining))
	reset := ceilSeconds(decision.ResetAt.Sub(now))
	if reset < 0 {
		reset = 0
	}
	header.Set("RateLimit-Reset", strconv.FormatInt(reset, 10))
}

func ceilSeconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	seconds := int64(d / time.Second)
	if d%time.Second != 0 {
		seconds++
	}
	return seconds
}

func hashIdentifier(rule, identifier string) string {
	sum := sha256.Sum256([]byte(rule + "\x00" + identifier))
	return hex.EncodeToString(sum[:16])
}
