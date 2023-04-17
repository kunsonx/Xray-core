package conf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/xtls/xray-core/proxy/wireguard"
)

type NordServer struct {
	ID           uint   `json:"id"`
	Name         string `json:"name"`
	Hostname     string `json:"hostname"`
	Technologies []struct {
		ID       uint   `json:"id"`
		Name     string `json:"name"`
		Metadata []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"metadata"`
	} `json:"technologies"`
}

type NordWireGuardConfig WireGuardConfig

func (c *NordWireGuardConfig) Build() (proto.Message, error) {
	cfg, err := (*WireGuardConfig)(c).Build()
	if err != nil {
		return nil, err
	}

	hostname, publicKey, err := c.RecommendedEndpoint()
	if err != nil {
		return nil, err
	}

	publicKey, err = parseWireGuardKey(publicKey)
	if err != nil {
		return nil, err
	}

	deviceCfg := cfg.(*wireguard.DeviceConfig)
	for _, p := range deviceCfg.Peers {
		p.Endpoint = fmt.Sprintf("%s:51820", hostname)
		p.PublicKey = publicKey
	}

	ctllog.Printf("nord recommended endpoint: %s %s\n", hostname, publicKey)
	return cfg, nil
}

func (c *NordWireGuardConfig) RecommendedEndpoint() (hostname, publicKey string, err error) {
	recommendedAPIURL := `https://api.nordvpn.com/v1/servers/recommendations?&filters\[servers_technologies\]\[identifier\]=wireguard_udp&limit=25`
	rsp, err := http.Get(recommendedAPIURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to get recommended server: %w", err)
	}
	defer rsp.Body.Close()
	d, err := io.ReadAll(rsp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read response body: %w", err)
	}

	var servers []NordServer
	if err = json.Unmarshal(d, &servers); err != nil {
		return "", "", fmt.Errorf("failed to decode response body: %w", err)
	}

	var nodes [][]string
	for _, s := range servers {
		for _, t := range s.Technologies {
			if t.Name == "Wireguard" {
				for _, m := range t.Metadata {
					if m.Name == "public_key" {
						nodes = append(nodes, []string{s.Hostname, m.Value})
					}
				}
			}
		}
	}
	if len(nodes) == 0 {
		return "", "", errors.New("nord empty recommended endpoint")
	}
	node := nodes[rand.Intn(len(nodes))]
	return node[0], node[1], nil
}
