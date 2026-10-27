package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"
)

var defaultPorts = []int{
	22,   //ssh
	80,   //http
	443,  //https
	3306, //mysql
	3389, //rdp
	6379, //redis
	8080, //http-alt
}

type PortTask struct {
	IP   string
	Port int
}

type PortResult struct {
	IP     string
	Port   int
	Open   bool
	Banner string
}

type PortsClient struct {
	ports   []int
	timeout time.Duration
	workers int
}

func NewPortsClient() *PortsClient {
	return &PortsClient{
		ports:   defaultPorts,
		timeout: 1 * time.Second,
		workers: 40,
	}
}

func (c *PortsClient) ScanPorts(ctx context.Context, ip string) ([]int, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("ports: invalid ip %q", ip)
	}

	tasks := make(chan PortTask, len(c.ports))
	results := make(chan PortResult, len(c.ports))

	go func() {
		defer close(tasks)
		for _, port := range c.ports {
			select {
			case tasks <- PortTask{IP: ip, Port: port}:
			case <-ctx.Done():
				return
			}
		}
	}()

	runPool(ctx, c.workers, tasks, results, func(ctx context.Context, t PortTask) (PortResult, bool) {
		open := c.isOpen(ctx, t.IP, t.Port)
		return PortResult{IP: t.IP, Port: t.Port, Open: open}, open
	})

	var open []int
	for r := range results {
		if r.Open {
			open = append(open, r.Port)
		}
	}

	if err := ctx.Err(); err != nil {
		return open, err
	}

	sort.Ints(open)
	return open, nil
}

func (c *PortsClient) ScanPortsMany(ctx context.Context, ips []string) (map[string][]int, error) {
	result := make(map[string][]int, len(ips))

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		ports, err := c.ScanPorts(ctx, ip)
		if err != nil {
			continue
		}
		if len(ports) > 0 {
			result[ip] = ports
		}
	}
	return result, nil
}

func (c *PortsClient) isOpen(ctx context.Context, ip string, port int) bool {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	dialer := &net.Dialer{Timeout: c.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true

}
