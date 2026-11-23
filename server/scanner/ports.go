package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
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
	unique := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
	}

	// Последовательный обход 66 IP занимал основную часть времени.
	// Ограниченный пул: каждый ScanPorts внутри уже использует 40 воркеров,
	// поэтому 8 IP одновременно = ~320 сокетов, а не тысячи.
	const ipConcurrency = 8
	sem := make(chan struct{}, ipConcurrency)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		result   = make(map[string][]int, len(unique))
	)
	for _, ip := range unique {
		ip := ip
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ports, err := c.ScanPorts(ctx, ip)
			if err != nil {
				mu.Lock()
				if firstErr == nil && ctx.Err() != nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			if len(ports) > 0 {
				mu.Lock()
				result[ip] = ports
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return result, firstErr
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
