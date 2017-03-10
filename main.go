// Copyright (c) 2016 The HADES Authors. All rights reserved.


package main

import (

	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	etcd "github.com/coreos/etcd/client"
	backendetcd "github.com/ipdcode/hades/backends/etcd"
	"github.com/ipdcode/hades/msg"
	"github.com/ipdcode/hades/server"
	"github.com/golang/glog"
	"golang.org/x/net/context"
)

const (
	glogFlushPeriod       = 5 * time.Second
)
var (
	tlskey     = ""
	tlspem     = ""
	cacert     = ""
	config     = &server.Config{ReadTimeout: 0, Domain: "", DnsAddr: ""}
	nameserver = ""
	machine    = ""
	version    = false

	statsServer     = ""
	statsServerAuthToken     = ""

)

func init() {
	flag.StringVar(&config.Domain, "domain",  "hades.local.", "domain to anchor requests")
	flag.StringVar(&config.DnsAddr, "addr",  "127.0.0.1:53", "ip:port mode , the addr to be bind)")

	flag.StringVar(&config.IpMonitorPath, "ip-monitor-path", "/hades/monitor/status/", "the ips to check available")
	flag.StringVar(&nameserver, "nameservers", "", "nameserver address(es) to forward (non-local) queries to e.g. 8.8.8.8:53,8.8.4.4:53")
	flag.StringVar(&machine, "machines", "", "machine address(es) running etcd")
	flag.StringVar(&tlskey, "tls-key",  "", "TLS Private Key path")
	flag.StringVar(&tlspem, "tls-pem", "", "X509 Certificate")
	flag.BoolVar(&version, "version",false, "Print version information and quit")
	flag.StringVar(&cacert, "ca-cert",  "", "CA Certificate")
	flag.DurationVar(&config.ReadTimeout, "rtimeout", 2*time.Second, "read timeout")

	flag.IntVar(&config.RCache, "rcache", server.RCacheCapacity, "capacity of the response cache")
	flag.IntVar(&config.RCacheTtl, "rcache-ttl", server.RCacheTtl, "TTL of the response cache")
	flag.StringVar(&statsServer, "statsServer",  "", "hades stats data server like 127.0.0.1:9600")
	flag.StringVar(&statsServerAuthToken, "statsServerAuthToken",  "@hades.com", "hades stats data server token")
        flag.BoolVar(&config.RadomOne, "radom-one", false, "pick radom one result for A")
	flag.BoolVar(&config.IpHold, "ip-hold", false, "pick the last ip(typeA) for the same client")

	flag.IntVar(&config.RCacheFlush, "rcache-flush", server.RCacheFlush, "the duration to flush expired cache out")
}

func glogFlush(period time.Duration) {
	for range time.Tick(period) {
		glog.Flush()
        }
}
func main() {
	flag.Parse()
	if version{
		fmt.Printf("%s\n",server.Version)
		return
	}
	go glogFlush(glogFlushPeriod)
	defer glog.Flush()

	machines := strings.Split(machine, ",")
	clientv2,err := newEtcdClient(machines)

	if err != nil {
		glog.Fatalf("hades:newEtcdClient: %s", err)
	}

	if nameserver != "" {
		for _, hostPort := range strings.Split(nameserver, ",") {
			if err := validateHostPort(hostPort); err != nil {
				glog.Fatalf("hades: nameserver is invalid: %s", err)
			}
			config.Nameservers = append(config.Nameservers, hostPort)
		}
	}
	if err := validateHostPort(config.DnsAddr); err != nil {
		glog.Fatalf("hades: addr is invalid: %s", err)
	}

	if err := server.SetDefaults(config); err != nil {
		glog.Fatalf("hades: defaults could not be set from /etc/resolv.conf: %v", err)
	}
	if config.IpHold && config.RadomOne{
		glog.Fatalf("hades: ipHold and radom-one you must chose one or neither, check config file !! \n")
	}

	var ctx        = context.Background()

	backend := backendetcd.NewBackend(clientv2, ctx, &backendetcd.Config{
		Ttl:      config.Ttl,
		Priority: config.Priority,
	})
	s := server.New(backend, config)

		 // watch ip status
	go func() {
		var watcher etcd.Watcher
		duration := 1 * time.Second
		watcher = clientv2.Watcher(msg.Path(config.Domain), &etcd.WatcherOptions{AfterIndex: 0, Recursive: true})
		for {
			r, err := watcher.Next(ctx)
		        if err != nil {
				glog.Infof("hades: watch ips sleeping %s ", duration)
				time.Sleep(duration)
				duration *= 2
				if duration > 32*time.Second {
					duration = 32 * time.Second
				}

			}else {
				s.UpdateRcache(r)
				duration = 1 * time.Second // reset
			}

		}
	}()

	// before server run we get the active ips
	ipWatchIdx := s.SyncHadesHostStatus()
	 // watch ip status
	go func() {
		var watcher etcd.Watcher
		duration := 1 * time.Second
		watcher = clientv2.Watcher(config.IpMonitorPath, &etcd.WatcherOptions{AfterIndex: ipWatchIdx, Recursive: true})
		for {
			r, err := watcher.Next(ctx)
		        if err != nil {
				glog.Infof("hades: watch ips sleeping %s ", duration)
				time.Sleep(duration)
				duration *= 2
				if duration > 32*time.Second {
					duration = 32 * time.Second
				}
			}else {
				s.UpdateHostStatus(r)
				duration = 1 * time.Second // reset
			}

		}
	}()


	go s.Statistics(statsServer,statsServerAuthToken) //

	if err := s.Run(); err != nil {
		glog.Fatalf("hades: %s", err)
	}
}

func validateHostPort(hostPort string) error {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil {
		return fmt.Errorf("bad IP address: %s", host)
	}

	if p, _ := strconv.Atoi(port); p < 1 || p > 65535 {
		return fmt.Errorf("bad port number %s", port)
	}
	return nil
}

func newEtcdClient(machines []string) (etcd.KeysAPI, error) {
	cli, err := etcd.New(etcd.Config{
		Endpoints: machines,
	})
	if err != nil {
		return nil, err
	}
	return etcd.NewKeysAPI(cli), nil
}

