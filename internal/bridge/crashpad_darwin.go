//go:build darwin

package bridge

type handlerTracker struct{}

func withCrashpadEnvironment(base []string, _, _ string) []string { return base }

func trackHandlers(string, string) *handlerTracker { return &handlerTracker{} }

func (*handlerTracker) close() error { return nil }
