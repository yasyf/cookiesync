//go:build darwin

package bridge

type handlerTracker struct{}

func crashpadEnvironment(string, string) []string { return nil }

func trackHandlers(string, string) *handlerTracker { return &handlerTracker{} }

func (*handlerTracker) close() error { return nil }
