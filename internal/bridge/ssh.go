package bridge

import (
	"errors"
	"slices"
	"strings"

	"github.com/yasyf/synckit/hostregistry"
)

func sealedSSHBase(target, dialAddress string) ([]string, string, error) {
	fact, err := hostregistry.Mesh.Host(target)
	if err != nil {
		return nil, "", err
	}
	user, address, ok := strings.Cut(dialAddress, "@")
	if !ok || user != fact.User || !slices.Contains(fact.Addresses, address) {
		return nil, "", errors.New("bridge: dial address is not in the registered SSH host fact")
	}
	knownHosts, err := hostregistry.Mesh.KnownHostsPath()
	if err != nil {
		return nil, "", err
	}
	if err := hostregistry.ValidateKnownHosts(knownHosts); err != nil {
		return nil, "", err
	}
	return []string{
		"-F", "/dev/null", "-T",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "KnownHostsCommand=none",
		"-o", "UpdateHostKeys=no",
		"-o", "CheckHostIP=no",
		"-o", "HostKeyAlias=" + fact.HostKeyAlias,
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "ProxyCommand=none",
		"-o", "ProxyJump=none",
		"-o", "CanonicalizeHostname=no",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "ForwardX11Trusted=no",
		"-o", "PermitLocalCommand=no",
		"-o", "RequestTTY=no",
		"-o", "EscapeChar=none",
		"-o", "ConnectTimeout=3",
		"-o", "ServerAliveInterval=5",
		"-o", "ServerAliveCountMax=3",
		"-l", fact.User,
	}, address, nil
}
