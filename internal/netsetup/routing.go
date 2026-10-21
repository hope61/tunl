package netsetup

import (
	"fmt"
	"net"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"

	"github.com/hope61/tunl/internal/config"
)

const (
	routingTable = 100
	FWMark       = fwMark
)

func ApplyAgentRouting(ifaceName, tunnelAddr, peerAddr string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("finding interface %s: %w", ifaceName, err)
	}

	serverIP := net.ParseIP(peerAddr).To4()
	if serverIP == nil {
		return fmt.Errorf("invalid peer address %q", peerAddr)
	}
	// Default route via tunnel for marked reply traffic
	route := &netlink.Route{
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Gw:        serverIP,
		LinkIndex: link.Attrs().Index,
		Table:     routingTable,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("adding route to table %d: %w", routingTable, err)
	}

	rule := netlink.NewRule()
	rule.Mark = FWMark
	rule.Table = routingTable
	rule.Priority = 100
	if err := addRuleIdempotent(rule); err != nil {
		return fmt.Errorf("adding ip rule for fwmark: %w", err)
	}

	return nil
}

func RemoveAgentRouting(ifaceName, peerAddr string) error {
	serverIP := net.ParseIP(peerAddr).To4()
	if serverIP != nil {
		route := &netlink.Route{
			Dst:   &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Gw:    serverIP,
			Table: routingTable,
		}
		netlink.RouteDel(route)
	}

	rule := netlink.NewRule()
	rule.Mark = FWMark
	rule.Table = routingTable
	rule.Priority = 100
	netlink.RuleDel(rule)

	return nil
}

func ApplyAgentConnmark(cfg *config.Config) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("connecting to nftables: %w", err)
	}

	tables, err := conn.ListTables()
	if err != nil {
		return fmt.Errorf("listing tables: %w", err)
	}
	var table *nftables.Table
	for _, t := range tables {
		if t.Name == tableName && t.Family == nftables.TableFamilyINet {
			table = t
			break
		}
	}
	if table == nil {
		return fmt.Errorf("tunl nftables table not found; run ApplyAgentRules first")
	}

	chainPrerouting := conn.AddChain(&nftables.Chain{
		Name:     "prerouting_mark",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: chainPriority(-390),
	})

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainPrerouting,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(cfg.Interface)},
			&expr.Ct{Register: 1, Key: expr.CtKeyMARK},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(FWMark)},
			&expr.Ct{Register: 1, Key: expr.CtKeyMARK, SourceRegister: true},
		},
	})

	chainOutput := conn.AddChain(&nftables.Chain{
		Name:     "output_mark",
		Table:    table,
		Type:     nftables.ChainTypeRoute,
		Hooknum:  nftables.ChainHookOutput,
		Priority: chainPriority(-390),
	})

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainOutput,
		Exprs: []expr.Any{
			&expr.Ct{Register: 1, Key: expr.CtKeyMARK},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(FWMark)},
			&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(FWMark)},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("applying connmark rules: %w", err)
	}
	return nil
}

func addRuleIdempotent(rule *netlink.Rule) error {
	existing, err := netlink.RuleList(syscall.AF_INET)
	if err != nil {
		return err
	}
	for _, r := range existing {
		if r.Mark == rule.Mark && r.Table == rule.Table {
			return nil
		}
	}
	return netlink.RuleAdd(rule)
}

func HasIPRule(mark uint32, table int) bool {
	rules, err := netlink.RuleList(syscall.AF_INET)
	if err != nil {
		return false
	}
	for _, r := range rules {
		if r.Mark == mark && r.Table == table {
			return true
		}
	}
	return false
}

func chainPriority(n int32) *nftables.ChainPriority {
	p := nftables.ChainPriority(n)
	return &p
}
