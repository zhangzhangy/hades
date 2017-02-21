// Copyright (c) 2014 The HADES Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package cache

import (
	"crypto/sha1"
	"sync"
	"time"
	"hash/fnv"
	"bytes"

	"github.com/miekg/dns"
	"github.com/golang/glog"
)

// Elem hold an answer and additional section that returned from the cache.
// The signature is put in answer, extra is empty there. This wastes some memory.
type elem struct {
	sync.Mutex
	expiration time.Time // time added + TTL, after this the elem is invalid
	msg        *dns.Msg
	mAnswer    map[string][]dns.RR // keep to return the pre RR for
	requestCount int64
	requestLastTine time.Time
	forwarding bool   // if true we don not check the ip
}

// Cache is a cache that holds on the a number of RRs or DNS messages. The cache
// eviction is randomized.
type Cache struct {
	sync.RWMutex
	capacity int
	m        map[string]*elem
	AvaliableIps   map[string] bool  // the host alive
	ttl      time.Duration
	pickRadomOne bool
	flushTime time.Duration

}

// every flushTime we radom check 10W record to del expired
func (c *Cache) flushExpiredCacheElem(){

	for range time.Tick(c.flushTime) {

		c.Lock()
		maxWalk := len(c.m)

		// 20ms 10W time.Since() calls in vm
		if maxWalk > 100000{
			maxWalk = 100000
		}
		i :=0
		for key,e := range(c.m){
			if time.Since(e.expiration) > 0 {
				delete(c.m, key)
				i++
			}
			maxWalk --
			if maxWalk ==0{
				break
			}
		}
		c.Unlock()
		if i >0{
			glog.Infof("%d elem exprired \n",i)
		}
        }
}

// New returns a new cache with the capacity and the ttl specified.
func New(capacity, ttl int, flush int,radomOne bool) *Cache {
	c := new(Cache)
	c.m = make(map[string]*elem)
	c.AvaliableIps = make(map[string]bool)
	c.capacity = capacity
	c.ttl = time.Duration(ttl) * time.Second
	c.flushTime = time.Duration(flush) * time.Second
	c.pickRadomOne = radomOne
	go c.flushExpiredCacheElem()
	return c
}

func (c *Cache) Capacity() int { return c.capacity }

func (c *Cache) CacheSizeUsed() int{
	c.RLock()
	defer c.RUnlock()
	return len(c.m)
}

func (c *Cache) Remove(s string) {
	c.Lock()
	delete(c.m, s)
	c.Unlock()
}
func (c *Cache)EnsureNoExist(name string,qtype  uint16, tcp bool)  {
	h := sha1.New()
	i := append([]byte(name), packUint16(qtype)...)
	if tcp {
		i = append(i, byte(254))
	}
	key:= string(h.Sum(i))
	c.Lock()
	if _, ok := c.m[key]; ok {
		glog.V(2).Infof("del key =%s type =%d\n",key,qtype)
		delete(c.m, key)
	}
	c.Unlock()
}

// the key in cache is diff from domain
func (c *Cache)keyTypeA(name string, dnssec, tcp bool) string {
	h := sha1.New()
	i := append([]byte(name), packUint16(dns.TypeA)...)
	if dnssec {
		i = append(i, byte(255))
	}
	if tcp {
		i = append(i, byte(254))
	}
	return string(h.Sum(i))
}
func (c *Cache) ShowCacheStats(domain string,tcp bool) (int64, time.Time){
	//udp
	c.RLock()
	defer c.RUnlock()
	key := c.keyTypeA(domain,false,tcp)
	if e, ok := c.m[key]; ok {
		return e.requestCount, e.requestLastTine
	}else{
		return 0,time.Time{}
	}
}
// the key in cache is diff from domain
func (c *Cache)keyExtendTypeA(name string, dnssec, tcp bool) string {
	h := sha1.New()
	t:=[]byte(name)  // del hades test.default.hades.local.hades. -->test.default.hades.local. 6: sizeof(hades.)
	i := append(t[:len(t)-6], packUint16(dns.TypeA)...)
	if dnssec {
		i = append(i, byte(255))
	}
	if tcp {
		i = append(i, byte(254))
	}
	return string(h.Sum(i))
}

func (c *Cache) checkCacheExitst(r interface{} ) (valueIdx int,keyExist bool,key string){

	var nameR string = ""
	var valA *dns.A = nil
	var valCname *dns.CNAME = nil

	keyExist = false
	valueIdx = -1
	key = ""
	switch r.(type) {
	case *dns.A:
		valA =  r.(*dns.A)
		nameR = valA.Hdr.Name
	case *dns.CNAME:
		valCname = r.(*dns.CNAME)
		nameR = valCname.Hdr.Name
	default:
		return valueIdx,keyExist,key
	}
	valueIdx = 0
	key = c.keyExtendTypeA(nameR, false,false)
	if e, ok := c.m[key]; ok {
		keyExist = true
		// Cname match specal value -1
		if valCname != nil{
			return -1, keyExist,key
		}
		// type A  match ,we compare the value
		for _, r := range e.msg.Answer {
			valAnswerA, b := r.(*dns.A)
			if b{
				ret := bytes.Compare(valA.A ,valAnswerA.A)
				if ret ==0 {
					return valueIdx, keyExist,key
				}
			}
			valueIdx += 1
		}
	}
	// the key find but no value use uadateset
	return valueIdx, keyExist,key
}
//del the val from the l2 level cache
func (c *Cache) delValFromDictL2(valA *dns.A ,l2Map map[string][]dns.RR ){
	for k, v := range l2Map {
		valAnswerA, b :=  v[0].(*dns.A)
		if b{
			ret := bytes.Compare(valA.A ,valAnswerA.A)
			if ret ==0 {
				delete(l2Map , k)
			}
		}

	}
	return
}
func (c *Cache) UpdateRcacheSet(val interface{}) {
	glog.V(2).Infof(" UpdateRcacheSet =%v\n",val)
	// type A we update the dict
	valA ,b := val.(*dns.A)
	if b != true {
		return
	}
	c.Lock()
	_, find, matchKey:= c.checkCacheExitst(valA)
	if find{
		//type A update the  Ansers
		e := c.m[matchKey]
		e.msg.Answer = append(e.msg.Answer, valA)
	}
	c.Unlock()
}

func (c *Cache) UpdateRcacheUpdate(valAOld interface{}, valANew interface{} ) {
	glog.V(2).Infof(" UpdateRcacheUpdate valAOld=%v valANew =%v\n",valAOld,valANew)
	c.Lock()
	defer c.Unlock()
	idx, find, matchKey:= c.checkCacheExitst(valAOld)
	//glog.Infof(" UpdateRcacheSet find =%v matchKey =%v \n",find,matchKey)
	if find{
		// cname match we del the key and return
		if idx < 0{
			delete(c.m, matchKey)
			return
		}
		//type A update the  Ansers
		e := c.m[matchKey]
		e.msg.Answer[idx] = valANew.(*dns.A)
		//del the old val from dict
		e.Lock()
		c.delValFromDictL2(valAOld.(*dns.A), e.mAnswer)
		e.Unlock()
	}
}
func (c *Cache) UpdateRcacheDelete(valA interface{}) {
	glog.V(2).Infof(" UpdateRcacheDelete =%v\n",valA)
	c.Lock()
	defer c.Unlock()
	idx, find,matchKey := c.checkCacheExitst(valA)
	//glog.Infof(" UpdateRcacheSet find =%v matchKey =%v \n",find,matchKey)
	if find{
		// cname match we del the key and return
		if idx < 0{
			delete(c.m, matchKey)
			return
		}
		//del form Ansers
		e := c.m[matchKey]

		e.msg.Answer = append(e.msg.Answer[:idx], e.msg.Answer[idx+1:]...)
		//del from dict
		e.Lock()
		c.delValFromDictL2(valA.(*dns.A), e.mAnswer)
		e.Unlock()
	}
}
// EvictRandom removes a 100 member a the cache.
// Must be called under a write lock.
func (c *Cache) EvictRandom() {
	clen := len(c.m)
	if clen <= c.capacity {
		return
	}
	i := 100
	for k, _ := range c.m {
		delete(c.m, k)
		i--
		if i == 0 {
			break
		}
	}
}

// InsertMessage inserts a message in the Cache. We will cache it for ttl seconds, which
// should be a small (60...300) integer.
func (c *Cache) InsertMessage(s string, msg *dns.Msg, remoteIp string, timeNow time.Time,forwarding bool) {
	if c.capacity <= 0 {
		if  c.pickRadomOne &&  len(msg.Answer) > 0{
			Answer := c.pickRadomOneFun(msg,remoteIp,forwarding)
			if len(Answer) > 0{
				msg.Answer = Answer
			}
		}
		return
	}
	c.Lock()
	if _, ok := c.m[s]; !ok {
		elm := &elem{expiration:time.Now().UTC().Add(c.ttl), msg:msg.Copy()}
		elm.mAnswer = make(map[string][]dns.RR)
		elm.requestCount =1
		elm.requestLastTine = timeNow
		elm.forwarding = forwarding
		c.m[s] = elm
		if len(msg.Answer) > 0 {
			c.cacheMsgPack(elm, msg, remoteIp)
		}
	}
	c.EvictRandom()
	c.Unlock()
}

// InsertSignature inserts a signature, the expiration time is used as the cache ttl.
func (c *Cache) InsertSignature(s string, sig *dns.RRSIG) {
	if c.capacity <= 0 {
		return
	}
	c.Lock()

	if _, ok := c.m[s]; !ok {
		m := ((int64(sig.Expiration) - time.Now().Unix()) / (1 << 31)) - 1
		if m < 0 {
			m = 0
		}
		t := time.Unix(int64(sig.Expiration)-(m*(1<<31)), 0).UTC()
		c.m[s] = &elem{expiration:t, msg: &dns.Msg{Answer: []dns.RR{dns.Copy(sig)}}}
	}
	c.EvictRandom()
	c.Unlock()
}


// pack the msg return the pre svc ip or the random one
func (c *Cache) pickRadomOneFun(msg *dns.Msg,remoteIp string, forwarding bool)( []dns.RR ){
	var ips []int
	var mAnswer []dns.RR
	// when each ip is not avaliable retrun the fist one
	ensureOneIp := 0
	for i, r := range msg.Answer {
		 switch r.(type) {
		 	case *dns.A:
				// choose the first one
				if ensureOneIp ==0{
					ensureOneIp = i
				}
				valA := r.(*dns.A)
				key := valA.A.String()
				if ! forwarding{
					if _,e:= c.AvaliableIps[key]; e{
						ips = append(ips,i)
					}
				}else{
					ips = append(ips,i)
				}

		 	case *dns.CNAME:
				mAnswer = append(mAnswer ,r)
			 // other type return org val
		    default:
			    var mAnswerNop []dns.RR
			    return mAnswerNop

		 }
	}
	// no hosts avaluable choose one
	if len(ips) ==0{
		ips = append(ips,ensureOneIp)
	}

	h := fnv.New32a()
	h.Write([]byte(remoteIp))
	idx := int(h.Sum32()) % len(ips)
	answerNew := msg.Answer[ips[idx]]
	mAnswer = append(mAnswer,answerNew)
	return mAnswer
}

func (c *Cache) cacheMsgPack(e *elem,msg *dns.Msg,remoteIp string) {
	if ! c.pickRadomOne {
		return
	}
	//if has pre query value return pre
	e.Lock()
	defer e.Unlock()
	if answer, ok := e.mAnswer[remoteIp]; ok {
		if e.forwarding {
			msg.Answer = answer
			return
		}
		// check avliable
		avliable := false
		for _, r := range answer {
			if valA, ok := r.(*dns.A); ok {
				key := valA.A.String()
				if _, e := c.AvaliableIps[key]; e {
					avliable = true
				}
			}
		}
		if avliable {
			msg.Answer = answer
			return
		} else {
			delete(e.mAnswer, remoteIp)
		}
	}
	Answer := c.pickRadomOneFun(msg, remoteIp, e.forwarding)
	if len(Answer )> 0 {
		e.mAnswer[remoteIp] = Answer[:]
		msg.Answer = Answer
	}
	return
}

// Search returns a dns.Msg, the expiration time and a boolean indicating if we found something
// in the cache.
func (c *Cache) DoSearch(s string,remoteIp string,queryNow time.Time) (*dns.Msg, time.Time, bool) {
	if c.capacity <= 0 {
		return nil, time.Time{}, false
	}
	c.RLock()
	if e, ok := c.m[s]; ok {
		e.requestLastTine = queryNow
		e.requestCount++
		e1 := e.msg.Copy()
		if len(e1.Answer) > 0 {
			c.cacheMsgPack(e, e1, remoteIp)
		}
		c.RUnlock()
		return e1, e.expiration, true
	}
	c.RUnlock()
	return nil, time.Time{}, false
}

// Key creates a hash key from a question section.

func Key(q dns.Question, tcp bool) string {
	h := sha1.New()
	i := append([]byte(q.Name), packUint16(q.Qtype)...)
	if tcp {
		i = append(i, byte(254))
	}
	return string(h.Sum(i))
}

func (c *Cache) Search(question dns.Question, tcp bool, msgid uint16,remoteIp string,queryNow time.Time) *dns.Msg {
	key := Key(question, tcp)
	m1, exp, hit := c.DoSearch(key,remoteIp,queryNow)
	if hit {
		// Cache hit! \o/
		if time.Since(exp) < 0 {
			m1.Id = msgid
			m1.Compress = true
			// Even if something ended up with the TC bit *in* the cache, set it to off
			m1.Truncated = false
			return m1
		}
		// Expired! /o\
		c.Remove(key)
	}
	return nil
}

func packUint16(i uint16) []byte { return []byte{byte(i >> 8), byte(i)} }

