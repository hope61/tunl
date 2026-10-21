package netsetup

import (
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"

	"github.com/hope61/tunl/internal/config"
)

const (
	tableName = "tunl"
	fwMark    = 0x54554e4c // "TUNL" in hex
)

func ApplyServerRules(cfg *config.Config) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("connecting to nftables: %w", err)
	}

	deleteOwnTable(conn)

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})

	chainForward := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	chainPrerouting := conn.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	chainPostrouting := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	agentIP := net.ParseIP(cfg.PeerAddr).To4()
	if agentIP == nil {
		return fmt.Errorf("invalid peer address %q", cfg.PeerAddr)
	}

	for _, fwd := range cfg.Forwards {
		protoNum := protoNumber(fwd.Proto)
		destPort := fwd.Port
		toPort := fwd.ToPort
		if toPort == 0 {
			toPort = fwd.Port
		}

		addDNATRule(conn, chainPrerouting, table, protoNum, destPort, agentIP, toPort)
		addForwardAllowRule(conn, chainForward, table, protoNum, agentIP, toPort, cfg.Interface)

		if fwd.SNAT {
			tunnelIP := net.ParseIP(cfg.TunnelAddr).To4()
			addSNATRule(conn, chainPostrouting, table, protoNum, agentIP, tunnelIP)
		}
	}

	addMSSClamp(conn, chainForward, table, cfg.MTU)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("applying nftables rules: %w", err)
	}
	return nil
}

func ApplyAgentRules(cfg *config.Config) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("connecting to nftables: %w", err)
	}

	deleteOwnTable(conn)

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})

	chainInput := conn.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   policyPtr(nftables.ChainPolicyAccept),
	})

	for _, fwd := range cfg.Forwards {
		protoNum := protoNumber(fwd.Proto)
		port := fwd.Port
		if fwd.ToPort != 0 {
			port = fwd.ToPort
		}
		addInputAllowRule(conn, chainInput, table, protoNum, port, cfg.Interface)
	}

	addInputDropRule(conn, chainInput, table, cfg.Interface)

	addMSSClamp(conn, chainInput, table, cfg.MTU)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("applying agent nftables rules: %w", err)
	}
	return nil
}

func RemoveRules() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("connecting to nftables: %w", err)
	}
	deleteOwnTable(conn)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("removing nftables rules: %w", err)
	}
	return nil
}

func deleteOwnTable(conn *nftables.Conn) {
	conn.DelTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})
	// Flush the delete separately; ignore errors if the table doesn't exist yet
	conn.Flush()
}

func protoNumber(proto string) byte {
	if proto == "udp" {
		return 17
	}
	return 6
}

func policyPtr(p nftables.ChainPolicy) *nftables.ChainPolicy {
	return &p
}

func addDNATRule(conn *nftables.Conn, chain *nftables.Chain, table *nftables.Table, proto byte, destPort uint16, dnatIP net.IP, dnatPort uint16) {
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(destPort)},
			&expr.Immediate{Register: 1, Data: dnatIP},
			&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(dnatPort)},
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      2, // NFPROTO_IPV4
				RegAddrMin:  1,
				RegProtoMin: 2,
			},
		},
	})
}

func addForwardAllowRule(conn *nftables.Conn, chain *nftables.Chain, table *nftables.Table, proto byte, destIP net.IP, destPort uint16, iface string) {
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(iface)},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: destIP},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(destPort)},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
}

func addSNATRule(conn *nftables.Conn, chain *nftables.Chain, table *nftables.Table, proto byte, destIP, srcIP net.IP) {
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: destIP},
			&expr.Immediate{Register: 1, Data: srcIP},
			&expr.NAT{
				Type:       expr.NATTypeSourceNAT,
				Family:     2,
				RegAddrMin: 1,
			},
		},
	})
}

func addInputAllowRule(conn *nftables.Conn, chain *nftables.Chain, table *nftables.Table, proto byte, port uint16, iface string) {
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(iface)},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
}

func addInputDropRule(conn *nftables.Conn, chain *nftables.Chain, table *nftables.Table, iface string) {
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(iface)},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})
}

func addMSSClamp(conn *nftables.Conn, chain *nftables.Chain, table *nftables.Table, mtu int) {
	mss := uint16(mtu - 40 - 20) // IPv4 header - TCP header
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // TCP only
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       13,
				Len:          1,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            1,
				Mask:           []byte{0x02}, // SYN flag
				Xor:            []byte{0x00},
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00}},
			&expr.Exthdr{
				DestRegister: 1,
				Type:         2, // TCPOPT_MAXSEG
				Offset:       2,
				Len:          2,
				Op:           expr.ExthdrOpTcpopt,
			},
			&expr.Cmp{Op: expr.CmpOpGt, Register: 1, Data: binaryutil.BigEndian.PutUint16(mss)},
			&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(mss)},
			&expr.Exthdr{
				SourceRegister: 1,
				Type:           2,
				Offset:         2,
				Len:            2,
				Op:             expr.ExthdrOpTcpopt,
			},
		},
	})
}

func ifnameBytes(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}

func GetTableRules() ([]*nftables.Rule, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, err
	}
	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
	}
	var rules []*nftables.Rule
	for _, t := range tables {
		if t.Name == tableName && t.Family == nftables.TableFamilyINet {
			chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
			if err != nil {
				return nil, err
			}
			for _, c := range chains {
				if c.Table.Name == tableName {
					r, err := conn.GetRules(t, c)
					if err != nil {
						return nil, err
					}
					rules = append(rules, r...)
				}
			}
		}
	}
	return rules, nil
}

func TableExists() bool {
	conn, err := nftables.New()
	if err != nil {
		return false
	}
	tables, err := conn.ListTables()
	if err != nil {
		return false
	}
	for _, t := range tables {
		if t.Name == tableName && t.Family == nftables.TableFamilyINet {
			return true
		}
	}
	return false
}
