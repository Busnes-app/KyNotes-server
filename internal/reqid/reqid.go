// Package reqid carries the request ID established by trusted HTTP middleware.
package reqid

import "context"

type key struct{}

// With records an ID after the middleware has applied its proxy trust policy.
func With(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, key{}, id)
}

// FromContext never falls back to a caller-supplied header.
func FromContext(ctx context.Context) string {
	id, _ := ctx.Value(key{}).(string)
	return id
}
