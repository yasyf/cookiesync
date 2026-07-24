package bridge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/yasyf/daemonkit/proc"
)

const childSettlementTimeout = 10 * time.Second

type preparedRecorder func(context.Context, proc.ProcessReceipt) error

func bridgeEnvironment() []string {
	keys := map[string]string{}
	for _, variable := range os.Environ() {
		key, _, ok := strings.Cut(variable, "=")
		if !ok || key == "PATH" || key == "LANG" {
			continue
		}
		if key == "HOME" || key == "USER" || key == "LOGNAME" || key == "TMPDIR" || key == "XDG_CONFIG_HOME" ||
			strings.HasPrefix(key, "COOKIESYNC_") || strings.HasPrefix(key, "SSH_") {
			keys[key] = variable
		}
	}
	environment := make([]string, 0, len(keys))
	for _, variable := range keys {
		environment = append(environment, variable)
	}
	slices.Sort(environment)
	return environment
}

func prepareChild(
	ctx context.Context,
	manager *proc.Manager,
	config proc.SpawnConfig,
	recorded preparedRecorder,
) (*proc.PreparedChild, proc.ProcessReceipt, error) {
	if manager == nil {
		return nil, proc.ProcessReceipt{}, errors.New("bridge: process manager is required")
	}
	request, err := proc.NewSpawnRequest(config)
	if err != nil {
		return nil, proc.ProcessReceipt{}, err
	}
	child, receipt, err := manager.Prepare(ctx, request)
	if err != nil {
		return nil, proc.ProcessReceipt{}, err
	}
	if recorded != nil {
		if err := recorded(ctx, receipt); err != nil {
			return nil, proc.ProcessReceipt{}, stopPreparedChild(ctx, child, fmt.Errorf("bridge: record prepared child: %w", err))
		}
	}
	return child, receipt, nil
}

func stopPreparedChild(parent context.Context, child *proc.PreparedChild, cause error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), childSettlementTimeout)
	defer cancel()
	return errors.Join(cause, child.Stop(ctx))
}
