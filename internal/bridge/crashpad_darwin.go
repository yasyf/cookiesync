//go:build darwin

package bridge

type handlerTracker struct{}

func crashpadEnvironment(string) []string { return nil }

func trackHandlers(string) *handlerTracker { return &handlerTracker{} }

func (*handlerTracker) close() error { return nil }
