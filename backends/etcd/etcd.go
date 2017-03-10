// Copyright (c) 2014 The HADES Authors. All rights reserved.

package etcd

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	etcd "github.com/coreos/etcd/client"
	"golang.org/x/net/context"
	"github.com/ipdcode/hades/msg"
)

// Config represents configuration for the Etcd backend - these values
// should be taken directly from server.Config
type Config struct {
	Ttl      uint32
	Priority uint16
}

type Backend struct {
	client   etcd.KeysAPI
	ctx      context.Context
	config   *Config
	singleInflight *etcdSingle
}

// NewBackend returns a new Backend for HADES, backed by etcd.
func NewBackend(client etcd.KeysAPI, ctx context.Context, config *Config) *Backend {
	return &Backend{
		client:   client,
		ctx:      ctx,
		config:   config,
		singleInflight: new(etcdSingle),
	}
}

func (g *Backend) Records(name string, exact bool) ([]msg.Service, error) {
	path, star := msg.PathWithWildcard(name)
	r, err := g.get(path, true)
	if err != nil {
		return nil, err
	}
	segments := strings.Split(msg.Path(name), "/")
	switch {
	case exact && r.Node.Dir:
		return nil, nil
	case r.Node.Dir:
		return g.loopNodes(&r.Node.Nodes, segments, star, nil)
	default:
		return g.loopNodes(&etcd.Nodes{r.Node}, segments, false, nil)
	}
}


func (g *Backend) ParseRecords(node *etcd.Node) ([]msg.Service, error){
	return g.loopNodes(&etcd.Nodes{node}, nil, false, nil)
}

func (g *Backend) Get(path string) (*etcd.Response, error){
	r, err := g.get(path, true)
	if err != nil {
		return nil, err
	}
	return r,err
}

func (g *Backend) ReverseRecord(name string) (*msg.Service, error) {
	path, star := msg.PathWithWildcard(name)
	if star {
		return nil, fmt.Errorf("reverse can not contain wildcards")
	}
	r, err := g.get(path, true)
	if err != nil {
		return nil, err
	}
	if r.Node.Dir {
		return nil, fmt.Errorf("reverse must not be a directory")
	}
	segments := strings.Split(msg.Path(name), "/")
	records, err := g.loopNodes(&etcd.Nodes{r.Node}, segments, false, nil)
	if err != nil {
		return nil, err
	}
	if len(records) != 1 {
		return nil, fmt.Errorf("must be only one service record")
	}
	return &records[0], nil
}

// get is a wrapper for client.Get that uses SingleInflight to suppress multiple
// outstanding queries.
func (g *Backend) get(path string, recursive bool) (*etcd.Response, error) {
	resp, err, _ := g.singleInflight.Do(path, func() (*etcd.Response, error) {
		r, e := g.client.Get(g.ctx, path, &etcd.GetOptions{Sort: true, Recursive: recursive})
		if e != nil {
			return nil, e
		}
		return r, e
	})
	if err != nil {
		return nil, err
	}
	return resp, err
}

type bareService struct {
	Host     string
	Port     int
	Priority int
	Weight   int
	Text     string
}

// loopNodes recursively loops through the nodes and returns all the values. The nodes' keyname
// will be match against any wildcards when star is true.
func (g *Backend) loopNodes(n *etcd.Nodes, nameParts []string, star bool, bx map[bareService]bool) (sx []msg.Service, err error) {
	if bx == nil {
		bx = make(map[bareService]bool)
	}
Nodes:
	for _, n := range *n {
		if n.Dir {
			nodes, err := g.loopNodes(&n.Nodes, nameParts, star, bx)
			if err != nil {
				return nil, err
			}
			sx = append(sx, nodes...)
			continue
		}
		if star {
			keyParts := strings.Split(n.Key, "/")
			for i, n := range nameParts {
				if i > len(keyParts)-1 {
					// name is longer than key
					continue Nodes
				}
				if n == "*" || n == "any" {
					continue
				}
				if keyParts[i] != n {
					continue Nodes
				}
			}
		}
		serv := new(msg.Service)
		if err := json.Unmarshal([]byte(n.Value), serv); err != nil {
			return nil, err
		}
		b := bareService{serv.Host, serv.Port, serv.Priority, serv.Weight, serv.Text}
		if _, ok := bx[b]; ok {
			continue
		}
		bx[b] = true

		serv.Key = n.Key
		serv.Ttl = g.calculateTtl(n, serv)
		if serv.Priority == 0 {
			serv.Priority = int(g.config.Priority)
		}
		sx = append(sx, *serv)
	}
	return sx, nil
}

// calculateTtl returns the smaller of the etcd TTL and the service's
// TTL. If neither of these are set (have a zero value), the server
// default is used.
func (g *Backend) calculateTtl(node *etcd.Node, serv *msg.Service) uint32 {
	etcdTtl := uint32(node.TTL)

	if etcdTtl == 0 && serv.Ttl == 0 {
		return g.config.Ttl
	}
	if etcdTtl == 0 {
		return serv.Ttl
	}
	if serv.Ttl == 0 {
		return etcdTtl
	}
	if etcdTtl < serv.Ttl {
		return etcdTtl
	}
	return serv.Ttl
}

// Client exposes the underlying Etcd client.
func (g *Backend) Client() etcd.KeysAPI{
	return g.client
}


type etcdCall struct {
	wg   sync.WaitGroup
	val  *etcd.Response
	err  error
	dups int
}

type etcdSingle struct {
	sync.Mutex
	m map[string]*etcdCall
}

func (g *etcdSingle) Do(key string, fn func() (*etcd.Response, error)) (*etcd.Response, error, bool) {
	g.Lock()
	if g.m == nil {
		g.m = make(map[string]*etcdCall)
	}
	if c, ok := g.m[key]; ok {
		c.dups++
		g.Unlock()
		c.wg.Wait()
		return c.val, c.err, true
	}
	c := new(etcdCall)
	c.wg.Add(1)
	g.m[key] = c
	g.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.Lock()
	delete(g.m, key)
	g.Unlock()

	return c.val, c.err, c.dups > 0
}
