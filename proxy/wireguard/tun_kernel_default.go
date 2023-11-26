//go:build !linux

package wireguard

import (
	"errors"
	"net/netip"
)

func createKernelTun(localAddresses []netip.Addr, mtu int, handler promiscuousModeHandler) (t Tunnel, err error) {
	return nil, errors.New("not implemented kernel tunnel for non-linux system")
}
