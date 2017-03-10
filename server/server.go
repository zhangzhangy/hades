// Copyright (c) 2014 The HADES Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	etcd "github.com/coreos/etcd/client"
	"github.com/miekg/dns"
	"github.com/ipdcode/hades/cache"
	"github.com/ipdcode/hades/msg"
	"github.com/golang/glog"
	"fmt"
	"math"
	"sync/atomic"
)

const Version = "1.1.2"

type server struct {
	backend Backend
	config  *Config

	group        *sync.WaitGroup
	dnsUDPclient *dns.Client // used for forwarding queries
	dnsTCPclient *dns.Client // used for forwarding queries
	rcache       *cache.Cache
	ipMonitorPath  string
}

type Backend interface {
	Records(name string, exact bool) ([]msg.Service, error)
	ReverseRecord(name string) (*msg.Service, error)
	ParseRecords(node *etcd.Node) ([]msg.Service, error)
	Get(path string) (*etcd.Response, error)
}

// FirstBackend exposes the Backend interface over multiple Backends, returning
// the first Backend that answers the provided record request. If no Backend answers
// a record request, the last error seen will be returned.
type FirstBackend []Backend

// FirstBackend implements Backend
var _ Backend = FirstBackend{}

func (g FirstBackend) Records(name string, exact bool) (records []msg.Service, err error) {
	var lastError error
	for _, backend := range g {
		if records, err = backend.Records(name, exact); err == nil && len(records) > 0 {
			return records, nil
		}
		if err != nil {
			lastError = err
		}
	}
	return nil, lastError
}

func (g FirstBackend) ParseRecords(node *etcd.Node) (records []msg.Service, err error) {
	var lastError error
	for _, backend := range g {
		if records, err = backend.ParseRecords(node); err == nil && len(records) > 0 {
			return records, nil
		}
		if err != nil {
			lastError = err
		}
	}
	return nil, lastError
}
func (g FirstBackend)Get(path string) (records *etcd.Response, err error) {
	var lastError error
	for _, backend := range g {
		if records, err = backend.Get(path); err == nil {
			return records, nil
		}
		if err != nil {
			lastError = err
		}
	}
	return nil, lastError
}

func (g FirstBackend) ReverseRecord(name string) (record *msg.Service, err error) {
	var lastError error
	for _, backend := range g {
		if record, err = backend.ReverseRecord(name); err == nil && record != nil {
			return record, nil
		}
		if err != nil {
			lastError = err
		}
	}
	return nil, lastError
}

// New returns a new HADES server.
func New(backend Backend, config *Config) *server {
	return &server{
		backend: backend,
		config:  config,

		group:        new(sync.WaitGroup),
		rcache:       cache.New(config.RCache, config.RCacheTtl,config.RCacheFlush,config.RadomOne,config.IpHold),
		dnsUDPclient: &dns.Client{Net: "udp", ReadTimeout: config.ReadTimeout, WriteTimeout: config.ReadTimeout, SingleInflight: true},
		dnsTCPclient: &dns.Client{Net: "tcp", ReadTimeout: config.ReadTimeout, WriteTimeout: config.ReadTimeout, SingleInflight: true},
		ipMonitorPath : config.IpMonitorPath,
	}
}


func (s *server)getSvcDomainName(key string) string{
	keys := strings.Split(key,"/")
	domLen := len(keys)-1
	for i, j := 0,domLen; i < j; i, j = i+1, j-1 {
		keys[i], keys[j] = keys[j], keys[i]
	}
	domainKey := strings.Join(keys[1:], ".") // ingoore the first
	//glog.Infof("domainKey =%s\n",domainKey )
	return domainKey
}
func (s *server)getSvcCnameName(key string) string{
	keys := strings.Split(key,"/")
	domLen := len(keys)-1
	for i, j := 0,domLen; i < j; i, j = i+1, j-1 {
		keys[i], keys[j] = keys[j], keys[i]
	}
	domainKey := strings.Join(keys, ".")
	return domainKey
}

func (s *server) updateRcacheParseRecord(node *etcd.Node) interface{} {
	records, err := s.backend.ParseRecords(node)
	if err != nil {
		glog.Infof("ParseRecords err %s \n",err.Error() )
		return nil
	}
	if len(records)==0 { // no result it is a dir
		return nil
	}
	ip := net.ParseIP(records[0].Host)
	switch {
	case ip == nil:
		name := s.getSvcCnameName(records[0].Key)
		name = name[:len(name)-6]
		return records[0].NewCNAME(name, dns.Fqdn(records[0].Host))
	case ip.To4() != nil:
		name := s.getSvcDomainName(records[0].Key)
		name = name[:len(name)-6]
		return records[0].NewA(name, ip.To4())
	default:
		glog.Infof("updateRcacheParseRecord err \n" )
	}

  	return nil
}
func (s *server) checkUpdateRcacheDir(resp *etcd.Response)(bool){
	// if /hades/local/hades/dns txt mail retrun true
	domaiNanme := msg.Domain(resp.Node.Key)
	if strings.HasSuffix(domaiNanme,s.config.dnsDomain){
		s.rcache.EnsureNoExist(s.config.Domain,dns.TypeNS ,false)
		return true
	}else if strings.HasSuffix(domaiNanme,s.config.mailDomain){
		s.rcache.EnsureNoExist(s.config.Domain,dns.TypeMX ,false)
		return true
	}else if strings.HasSuffix(domaiNanme,s.config.txtDomain){
		s.rcache.EnsureNoExist(s.config.Domain,dns.TypeTXT ,false)
		return true
	}else{
		return false
	}
}
func (s *server) UpdateRcache(resp *etcd.Response) {
        glog.V(2).Infof("UpdateRcache: Action =%s Key=%s", resp.Action, resp.Node.Key)
        if s.checkUpdateRcacheDir(resp){
		return
	}
	switch strings.ToLower(resp.Action){
		case "create":
			fallthrough
		case "set":
			valNew := s.updateRcacheParseRecord(resp.Node)
			var valOld interface{} = nil
			if resp.PrevNode != nil {
				valOld = s.updateRcacheParseRecord(resp.PrevNode)
			}
			if valNew != nil && valOld != nil{
				s.rcache.UpdateRcacheUpdate(valOld, valNew)
			}else if valNew != nil{
				s.rcache.UpdateRcacheSet(valNew)
                        }else{
				glog.Infof("UpdateRcache  set err \n" )
			}
		case "compareanddelete":
			fallthrough
 		case "delete":
			valA := s.updateRcacheParseRecord(resp.PrevNode)
			if valA != nil {
				s.rcache.UpdateRcacheDelete(valA)
                        }else{
				glog.Infof("UpdateRcache  del err \n" )
			}
		case "compareandswap":
			fallthrough
		case "update":
			valA := s.updateRcacheParseRecord(resp.Node)
			var valAOld interface{}  = nil
			if resp.PrevNode != nil{
				valAOld = s.updateRcacheParseRecord(resp.PrevNode)
			}
			if valA != nil && valAOld != nil{
				s.rcache.UpdateRcacheUpdate(valAOld, valA)
                        }else{
				glog.Infof("UpdateRcache  update err \n" )
			}
		default:
		    	glog.Infof("the action not monitored: Action =%s Key=%s", resp.Action, resp.Node.Key)

	}
}
// Run is a blocking operation that starts the server listening on the DNS ports.
func (s *server) Run() error {
	mux := dns.NewServeMux()
	mux.Handle(".", s)
	s.group.Add(1)
	go func() {
		defer s.group.Done()
		if err := dns.ListenAndServe(s.config.DnsAddr, "tcp", mux); err != nil {
			glog.Fatalf("%s", err)
		}
	}()
	glog.Infof("ready for queries on %s for %s://%s [rcache %d]", s.config.Domain, "tcp", s.config.DnsAddr, s.config.RCache)
	s.group.Add(1)
	go func() {
		defer s.group.Done()
		if err := dns.ListenAndServe(s.config.DnsAddr, "udp", mux); err != nil {
			glog.Fatalf("%s", err)
		}
	}()
	glog.Infof("ready for queries on %s for %s://%s [rcache %d]", s.config.Domain, "udp", s.config.DnsAddr, s.config.RCache)

	s.group.Wait()
	return nil
}

// Stop stops a server.
func (s *server) Stop() {
	glog.Infof("exit from hades\n")
}

func Fit(m *dns.Msg, size int, tcp bool) (*dns.Msg, bool) {
	if m.Len() > size {
		m.Extra = nil
	}
	if m.Len() < size {
		return m, false
	}

	// With TCP setting TC does not mean anything.
	if !tcp {
		m.Truncated = true
	}

	// Additional section is gone, binary search until we have length that fits.
	min, max := 0, len(m.Answer)
	original := make([]dns.RR, len(m.Answer))
	copy(original, m.Answer)
	for {
		if min == max {
			break
		}

		mid := (min + max) / 2
		m.Answer = original[:mid]

		if m.Len() < size {
			min++
			continue
		}
		max = mid

	}
	if max > 1 {
		max--
	}
	m.Answer = m.Answer[:max]
	return m, true
}
// ServeDNS is the handler for DNS requests, responsible for parsing DNS request, possibly forwarding
// it to a real dns server and returning a response.
func (s *server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.RecursionAvailable = true
	m.Compress = true
	bufsize := uint16(512)
	tcp := false
	timeNow := time.Now().Local()

	q := req.Question[0]
	name := strings.ToLower(q.Name)
	if q.Qtype == dns.TypeANY {
		m.Authoritative = false
		m.Rcode = dns.RcodeRefused
		m.RecursionAvailable = false
		m.RecursionDesired = false
		m.Compress = false
		// if write fails don't care
		w.WriteMsg(m)

		atomic.AddInt64(&statsErrorCountRefused,1)
		return
	}

	if bufsize < 512 {
		bufsize = 512
	}
	// with TCP we can send 64K
	if tcp = isTCP(w); tcp {
		bufsize = dns.MaxMsgSize - 1
		atomic.AddInt64(&statsRequestCountTcp, 1)
	} else {
		atomic.AddInt64(&statsRequestCountUdp,1)
	}
 	atomic.AddInt64(&statsRequestCount,1)

	glog.V(2).Infof("received DNS Request for %q from %q with type %d", q.Name, w.RemoteAddr(), q.Qtype)

	// Check cache first.
	remoteAddr := w.RemoteAddr().String() //10.8.65.158:42158
	remoteIp := strings.Split(remoteAddr, ":")
	m1 := s.rcache.Search(q, tcp, m.Id,remoteIp[0],timeNow)
	if m1 != nil {
		atomic.AddInt64(&statsRequestCountCached,1)
		glog.V(4).Infof("cache hit %q: %v\n ", q.Name,m1.Answer)
		if tcp {
			if _, overflow := Fit(m1, dns.MaxMsgSize, tcp); overflow {
				atomic.AddInt64(&statsErrorCountOverflow,1)
				msgFail := new(dns.Msg)
				s.ServerFailure(msgFail, req)
				w.WriteMsg(msgFail)
				return
			}
		} else {
			// Overflow with udp always results in TC.
			Fit(m1, int(bufsize), tcp)
			if m1.Truncated {
				atomic.AddInt64(&statsErrorCountTruncated,1)
			}
		}
		if err := w.WriteMsg(m1); err != nil {
			glog.Infof("failure to return reply %q", err)
		}
		return
	}
	if q.Qtype == dns.TypePTR && strings.HasSuffix(name, ".in-addr.arpa.") || strings.HasSuffix(name, ".ip6.arpa.") {
		resp := s.ServeDNSReverse(w, req,remoteIp[0],timeNow)
		glog.V(4).Infof("ServeDNSReverse %q: %v \n ", q.Name, resp.Answer)
		return
	}

	if q.Qclass != dns.ClassCHAOS && !strings.HasSuffix(name, s.config.Domain) {
		resp := s.ServeDNSForward(w, req,remoteIp[0],timeNow)
		glog.V(4).Infof("ServeDNSForward %q: %v \n ", q.Name, resp.Answer)
		return
	}
        atomic.AddInt64(&statsCacheMissResponse,1)

	defer func() {
		if m.Rcode == dns.RcodeServerFailure {
			if err := w.WriteMsg(m); err != nil {
				glog.Infof("failure to return reply %q", err)
			}
			return
		}
		// Set TTL to the minimum of the RRset and dedup the message, i.e. remove identical RRs.
		m = s.dedup(m)

		minttl := s.config.Ttl
		if len(m.Answer) > 1 {
			for _, r := range m.Answer {
				if r.Header().Ttl < minttl {
					minttl = r.Header().Ttl
				}
			}
			for _, r := range m.Answer {
				r.Header().Ttl = minttl
			}
		}

		if tcp {
			if _, overflow := Fit(m, dns.MaxMsgSize, tcp); overflow {
				msgFail := new(dns.Msg)
				s.ServerFailure(msgFail, req)
				w.WriteMsg(msgFail)
				return
			}
		} else {
			Fit(m, int(bufsize), tcp)
			if m.Truncated {
				atomic.AddInt64(&statsErrorCountTruncated,1)
			}
		}
		s.rcache.InsertMessage(cache.Key(q, tcp), m,remoteIp[0],timeNow,false)

		if err := w.WriteMsg(m); err != nil {
			glog.Infof("failure to return reply %q", err)
		}

	}()

	if q.Qclass == dns.ClassCHAOS {
		if q.Qtype == dns.TypeTXT {
			switch name {
			case "authors.bind.":
				fallthrough
			case s.config.Domain:
				hdr := dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0}
				authors := []string{"Chensg", "Li Guochao","Yang Wanli"}
				for _, a := range authors {
					m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{a}})
				}
				for j := 0; j < len(authors)*(int(dns.Id())%4+1); j++ {
					q := int(dns.Id()) % len(authors)
					p := int(dns.Id()) % len(authors)
					if q == p {
						p = (p + 1) % len(authors)
					}
					m.Answer[q], m.Answer[p] = m.Answer[p], m.Answer[q]
				}
				return
			case "version.bind.":
				fallthrough
			case "version.server.":
				hdr := dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0}
				m.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{Version}}}
				return
			case "hostname.bind.":
				fallthrough
			case "id.server.":
				hdr := dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0}
				m.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{"localhost"}}}
				return
			}
		}
		// still here, fail
		m.SetReply(req)
		m.SetRcode(req, dns.RcodeServerFailure)
		return
	}

	switch q.Qtype {
	case dns.TypeNS:
		if name != s.config.Domain {
			break
		}
		// Lookup s.config.DnsDomain
		records, extra, err := s.NSRecordsBind9Record(q, s.config.dnsDomain)
		if isEtcdNameError(err, s) {
			s.NameError(m, req)
			return
		}
		m.Answer = append(m.Answer, records...)
		m.Extra = append(m.Extra, extra...)
	case dns.TypeA, dns.TypeAAAA:
		// domain name return bind9 type
		if name == s.config.Domain {
			ns, extra, _ := s.NSRecordsBind9Record(q, s.config.dnsDomain)
			m.Ns = append(m.Ns, ns...)
			m.Extra = append(m.Extra, extra...)
                        dnsIpname := "dns-ip.dns." +s.config.Domain

			records, err := s.AddressRecords(q, dnsIpname, nil, bufsize, false)
			if isEtcdNameError(err, s) {
				s.NameError(m, req)
				return
			}
			m.Answer = append(m.Answer, records...)

		}else{
			records, err := s.AddressRecords(q, name, nil, bufsize, false)
			if isEtcdNameError(err, s) {
				s.NameError(m, req)
				return
			}
			m.Answer = append(m.Answer, records...)

		}

	case dns.TypeTXT:
		if name != s.config.Domain {
			break
		}
		records, err := s.TXTRecords(q, s.config.txtDomain)
		if isEtcdNameError(err, s) {
			s.NameError(m, req)
			return
		}
		m.Answer = append(m.Answer, records...)
	case dns.TypeCNAME:
		records, err := s.CNAMERecords(q, name)
		if isEtcdNameError(err, s) {
			s.NameError(m, req)
			return
		}
		m.Answer = append(m.Answer, records...)
	case dns.TypeMX:
		if name != s.config.Domain {
			break
		}
		records, extra, err := s.MXRecords(q, s.config.mailDomain, bufsize)
		if isEtcdNameError(err, s) {
			s.NameError(m, req)
			return
		}
		m.Answer = append(m.Answer, records...)
		m.Extra = append(m.Extra, extra...)
	default:
		fallthrough // also catch other types, so that they return NODATA
	case dns.TypeSRV:
		records, extra, err := s.SRVRecords(q, name, bufsize)
		if err != nil {
			if isEtcdNameError(err, s) {
				s.NameError(m, req)
				return
			}
			glog.Infof("got error from backend: %s", err)
			if q.Qtype == dns.TypeSRV { // Otherwise NODATA
				s.ServerFailure(m, req)
				return
			}
		}

		if q.Qtype == dns.TypeSRV {
			m.Answer = append(m.Answer, records...)
			m.Extra = append(m.Extra, extra...)
		}
	}

	if len(m.Answer) == 0 { // NODATA response
		atomic.AddInt64(&statsNoDataCount,1)
		m.Ns = []dns.RR{s.NewSOA()}
		m.Ns[0].Header().Ttl = s.config.MinTtl
	}
}

func (s *server) AddressRecords(q dns.Question, name string, previousRecords []dns.RR, bufsize uint16, both bool) (records []dns.RR, err error) {
	services, err := s.backend.Records(name, false)
	if err != nil {
		glog.Infof("AddressRecords err  %s q name=%s\n", err.Error(),q.Name)
		return nil, err
	}

	services = msg.Group(services)

	for _, serv := range services {
		if serv.Host == ""{
			continue
		}
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			// Try to resolve as CNAME if it's not an IP, but only if we don't create loops.
			if q.Name == dns.Fqdn(serv.Host) {
				// x CNAME x is a direct loop, don't add those
				continue
			}

			newRecord := serv.NewCNAME(q.Name, dns.Fqdn(serv.Host))
			if len(previousRecords) > 0 {
				glog.Infof("CNAME lookup limit of 1 exceeded for %s", newRecord)
				// don't add it, and just continue
				continue
			}
			if s.isDuplicateCNAME(newRecord, previousRecords) {
				glog.Infof("CNAME loop detected for record %s", newRecord)
				continue
			}

			nextRecords, err := s.AddressRecords(dns.Question{Name: dns.Fqdn(serv.Host), Qtype: q.Qtype, Qclass: q.Qclass},
				strings.ToLower(dns.Fqdn(serv.Host)), append(previousRecords, newRecord), bufsize, both)
			if err == nil {
				// Only have we found something we should add the CNAME and the IP addresses.
				if len(nextRecords) > 0 {
					records = append(records, newRecord) // we do not need the record just return the ip
					records = append(records, nextRecords...)
				}
				continue
			}
			// This means we can not complete the CNAME, try to look else where.
			target := newRecord.Target
			if dns.IsSubDomain(s.config.Domain, target) {
				// We should already have found it
				continue
			}
			m1, e1 := s.Lookup(target, q.Qtype, bufsize)
			if e1 != nil {
				glog.Infof("incomplete CNAME chain: %s", e1)
				continue
			}
			// Len(m1.Answer) > 0 here is well?
			records = append(records, newRecord)
			records = append(records, m1.Answer...)
			continue
		case ip.To4() != nil && (q.Qtype == dns.TypeA || both):
			records = append(records, serv.NewA(q.Name, ip.To4()))
		case ip.To4() == nil && (q.Qtype == dns.TypeAAAA || both):
			records = append(records, serv.NewAAAA(q.Name, ip.To16()))
		}
	}
	return records, nil
}

// NSRecords returns NS records from etcd.
func (s *server) NSRecords(q dns.Question, name string) (records []dns.RR, extra []dns.RR, err error) {
	services, err := s.backend.Records(name, false)
	if err != nil {
		return nil, nil, err
	}

	services = msg.Group(services)

	for _, serv := range services {
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			return nil, nil, fmt.Errorf("NS record must be an IP address")
		case ip.To4() != nil:
			serv.Host = msg.Domain(serv.Key)
			records = append(records, serv.NewNS(q.Name, serv.Host))
			extra = append(extra, serv.NewA(serv.Host, ip.To4()))
		case ip.To4() == nil:
			serv.Host = msg.Domain(serv.Key)
			records = append(records, serv.NewNS(q.Name, serv.Host))
			extra = append(extra, serv.NewAAAA(serv.Host, ip.To16()))
		}
	}
	return records, extra, nil
}

// NSRecords returns NS records from etcd.
func (s *server) NSRecordsBind9Record(q dns.Question, name string) (records []dns.RR, extra []dns.RR, err error) {
	services, err := s.backend.Records(name, false)
	if err != nil {
		return nil, nil, err
	}

	services = msg.Group(services)

	for _, serv := range services {
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			return nil, nil, fmt.Errorf("NS record must be an IP address")
		case ip.To4() != nil:
			domain := msg.Domain(serv.Key)
			domain = strings.Replace(domain, "ns.dns." ,"" ,1)
			serv.Host = domain
			records = append(records, serv.NewNS(q.Name, serv.Host))
			extra = append(extra, serv.NewA(serv.Host, ip.To4()))
		case ip.To4() == nil:
			domain := msg.Domain(serv.Key)
			domain = strings.Replace(domain, "ns.dns." ,"" ,1)
			serv.Host = domain
			records = append(records, serv.NewNS(q.Name, serv.Host))
			extra = append(extra, serv.NewAAAA(serv.Host, ip.To16()))
		}
	}
	return records, extra, nil
}
// SRVRecords returns SRV records from etcd.
// If the Target is not a name but an IP address, a name is created.
func (s *server) SRVRecords(q dns.Question, name string, bufsize uint16) (records []dns.RR, extra []dns.RR, err error) {
	services, err := s.backend.Records(name, false)
	if err != nil {
		return nil, nil, err
	}

	services = msg.Group(services)

	// Looping twice to get the right weight vs priority
	w := make(map[int]int)
	for _, serv := range services {
		weight := 100
		if serv.Weight != 0 {
			weight = serv.Weight
		}
		if _, ok := w[serv.Priority]; !ok {
			w[serv.Priority] = weight
			continue
		}
		w[serv.Priority] += weight
	}
	lookup := make(map[string]bool)
	for _, serv := range services {
		w1 := 100.0 / float64(w[serv.Priority])
		if serv.Weight == 0 {
			w1 *= 100
		} else {
			w1 *= float64(serv.Weight)
		}
		weight := uint16(math.Floor(w1))
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			srv := serv.NewSRV(q.Name, weight)
			records = append(records, srv)

			if _, ok := lookup[srv.Target]; ok {
				break
			}

			lookup[srv.Target] = true

			if !dns.IsSubDomain(s.config.Domain, srv.Target) {
				m1, e1 := s.Lookup(srv.Target, dns.TypeA, bufsize)
				if e1 == nil {
					extra = append(extra, m1.Answer...)
				}
				m1, e1 = s.Lookup(srv.Target, dns.TypeAAAA, bufsize)
				if e1 == nil {
					// If we have seen CNAME's we *assume* that they are already added.
					for _, a := range m1.Answer {
						if _, ok := a.(*dns.CNAME); !ok {
							extra = append(extra, a)
						}
					}
				}
				break
			}
			// Internal name, we should have some info on them, either v4 or v6
			// Clients expect a complete answer, because we are a recursor in their
			// view.
			addr, e1 := s.AddressRecords(dns.Question{srv.Target, dns.ClassINET, dns.TypeA},
				srv.Target, nil, bufsize, true)
			if e1 == nil {
				extra = append(extra, addr...)
			}
		case ip.To4() != nil:
			serv.Host = msg.Domain(serv.Key)
			srv := serv.NewSRV(q.Name, weight)

			records = append(records, srv)
			extra = append(extra, serv.NewA(srv.Target, ip.To4()))
		case ip.To4() == nil:
			serv.Host = msg.Domain(serv.Key)
			srv := serv.NewSRV(q.Name, weight)

			records = append(records, srv)
			extra = append(extra, serv.NewAAAA(srv.Target, ip.To16()))
		}
	}
	return records, extra, nil
}

// MXRecords returns MX records from etcd.
// If the Target is not a name but an IP address, a name is created.
func (s *server) MXRecords(q dns.Question, name string, bufsize uint16) (records []dns.RR, extra []dns.RR, err error) {
	services, err := s.backend.Records(name, false)
	if err != nil {
		return nil, nil, err
	}

	lookup := make(map[string]bool)
	for _, serv := range services {
		if !serv.Mail {
			continue
		}
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			mx := serv.NewMX(q.Name)
			records = append(records, mx)
			if _, ok := lookup[mx.Mx]; ok {
				break
			}

			lookup[mx.Mx] = true

			if !dns.IsSubDomain(s.config.Domain, mx.Mx) {
				m1, e1 := s.Lookup(mx.Mx, dns.TypeA, bufsize)
				if e1 == nil {
					extra = append(extra, m1.Answer...)
				}
				m1, e1 = s.Lookup(mx.Mx, dns.TypeAAAA, bufsize)
				if e1 == nil {
					// If we have seen CNAME's we *assume* that they are already added.
					for _, a := range m1.Answer {
						if _, ok := a.(*dns.CNAME); !ok {
							extra = append(extra, a)
						}
					}
				}
				break
			}
			// Internal name
			addr, e1 := s.AddressRecords(dns.Question{mx.Mx, dns.ClassINET, dns.TypeA},
				mx.Mx, nil, bufsize, true)
			if e1 == nil {
				extra = append(extra, addr...)
			}
		case ip.To4() != nil:
			serv.Host = msg.Domain(serv.Key)
			records = append(records, serv.NewMX(q.Name))
			extra = append(extra, serv.NewA(serv.Host, ip.To4()))
		case ip.To4() == nil:
			serv.Host = msg.Domain(serv.Key)
			records = append(records, serv.NewMX(q.Name))
			extra = append(extra, serv.NewAAAA(serv.Host, ip.To16()))
		}
	}
	return records, extra, nil
}

func (s *server) CNAMERecords(q dns.Question, name string) (records []dns.RR, err error) {
	services, err := s.backend.Records(name, true)
	if err != nil {
		return nil, err
	}

	services = msg.Group(services)

	if len(services) > 0 {
		serv := services[0]
		if ip := net.ParseIP(serv.Host); ip == nil {
			records = append(records, serv.NewCNAME(q.Name, dns.Fqdn(serv.Host)))
		}
	}
	return records, nil
}

func (s *server) TXTRecords(q dns.Question, name string) (records []dns.RR, err error) {
	services, err := s.backend.Records(name, false)
	if err != nil {
		return nil, err
	}

	services = msg.Group(services)

	for _, serv := range services {
		if serv.Text == "" {
			continue
		}
		records = append(records, serv.NewTXT(q.Name))
	}
	return records, nil
}

func (s *server) PTRRecords(q dns.Question) (records []dns.RR, err error) {
	name := strings.ToLower(q.Name)
	serv, err := s.backend.ReverseRecord(name)
	if err != nil {
		return nil, err
	}

	records = append(records, serv.NewPTR(q.Name, serv.Ttl))
	return records, nil
}

// SOA returns a SOA record for this HADES instance.
func (s *server) NewSOA() dns.RR {
	return &dns.SOA{Hdr: dns.RR_Header{Name: s.config.Domain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: s.config.Ttl},
		Ns:      appendDomain("ns1", s.config.Domain),
		Mbox:     s.config.hostMaster,
		Serial:  uint32(time.Now().Truncate(time.Hour).Unix()),
		Refresh: 28800,
		Retry:   7200,
		Expire:  604800,
		Minttl:  s.config.MinTtl,
	}
}

func (s *server) isDuplicateCNAME(r *dns.CNAME, records []dns.RR) bool {
	for _, rec := range records {
		if v, ok := rec.(*dns.CNAME); ok {
			if v.Target == r.Target {
				return true
			}
		}
	}
	return false
}

func (s *server) NameError(m, req *dns.Msg) {
	m.SetRcode(req, dns.RcodeNameError)
	m.Ns = []dns.RR{s.NewSOA()}
	m.Ns[0].Header().Ttl = s.config.MinTtl
	atomic.AddInt64(&statsErrorCountNoname,1)
}

func (s *server) NoDataError(m, req *dns.Msg) {
	m.SetRcode(req, dns.RcodeSuccess)
	m.Ns = []dns.RR{s.NewSOA()}
	m.Ns[0].Header().Ttl = s.config.MinTtl
	atomic.AddInt64(&statsNoDataCount,1)

}

func (s *server) ServerFailure(m, req *dns.Msg) {
	m.SetRcode(req, dns.RcodeServerFailure)
	atomic.AddInt64(&statsErrorCountServfail,1)
}

func (s *server) dedup(m *dns.Msg) *dns.Msg {
	// Answer section
	ma := make(map[string]dns.RR)
	for _, a := range m.Answer {
		// Or use Pack()... Think this function also could be placed in go dns.
		s1 := a.Header().Name
		s1 += strconv.Itoa(int(a.Header().Class))
		s1 += strconv.Itoa(int(a.Header().Rrtype))
		// there can only be one CNAME for an ownername
		if a.Header().Rrtype == dns.TypeCNAME {
			ma[s1] = a
			continue
		}
		for i := 1; i <= dns.NumField(a); i++ {
			s1 += dns.Field(a, i)
		}
		ma[s1] = a
	}
	// Only is our map is smaller than the #RR in the answer section we should reset the RRs
	// in the section it self
	if len(ma) < len(m.Answer) {
		i := 0
		for _, v := range ma {
			m.Answer[i] = v
			i++
		}
		m.Answer = m.Answer[:len(ma)]
	}

	// Additional section
	me := make(map[string]dns.RR)
	for _, e := range m.Extra {
		s1 := e.Header().Name
		s1 += strconv.Itoa(int(e.Header().Class))
		s1 += strconv.Itoa(int(e.Header().Rrtype))
		// there can only be one CNAME for an ownername
		if e.Header().Rrtype == dns.TypeCNAME {
			me[s1] = e
			continue
		}
		for i := 1; i <= dns.NumField(e); i++ {
			s1 += dns.Field(e, i)
		}
		me[s1] = e
	}

	if len(me) < len(m.Extra) {
		i := 0
		for _, v := range me {
			m.Extra[i] = v
			i++
		}
		m.Extra = m.Extra[:len(me)]
	}

	return m
}

// isTCP returns true if the client is connecting over TCP.
func isTCP(w dns.ResponseWriter) bool {
	_, ok := w.RemoteAddr().(*net.TCPAddr)
	return ok
}

func isEtcdNameError(err error, s *server) bool {
	if e, ok := err.(etcd.Error); ok && e.Code == etcd.ErrorCodeKeyNotFound {
		return true
	}
	if err != nil {
		glog.Infof("error from backend: %s", err)
	}
	return false
}
