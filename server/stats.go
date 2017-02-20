// Copyright (c) 2014 The HADES Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"net/http"
	"net"
	"fmt"
	"encoding/json"
	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"time"
	"strings"
)
var (
	statsErrorCountRefused int64 = 0
	statsErrorCountOverflow int64 = 0
	statsErrorCountTruncated int64 = 0
	statsErrorCountServfail  int64 =0
	statsErrorCountNoname    int64 =0

	statsRequestCountTcp   int64 = 0
	statsRequestCountUdp   int64 = 0
	statsRequestCount      int64 = 0
	statsForwardCount      int64 = 0
	statsCacheMissResponse int64 = 0

	statsStubForwardCount   int64 =0

	statsNoDataCount int64 = 0

	statsDnssecOkCount  int64 = 0
	statsDnssecCacheMiss int64 = 0
)

var statsAuthToken     = ""
type comStats struct {
	RequestCount int64 `json:"reqCount,omitempty"`
	ForwardCount int64 `json:"forwardCount,omitempty"`
	CacheMissCount int64 `json:"cacheMissCount,omitempty"`
	CacheSizeUsed int `json:"cacheSizeUsed,omitempty"`

	ErrorCountNoname int64 `json:"noNameCount,omitempty"`
	ErrorCountOverflow int64 `json:"overFlowCount,omitempty"`
	ErrorNoDataCount int64 `json:"noDataCount,omitempty"`

}
type domainStats struct {
	RequestCount int64 `json:"reqCount,omitempty"`
	LastQueryTime time.Time `json:"lastQueryTime,omitempty"`
}

func (s *server) statsList(w http.ResponseWriter, r *http.Request){

        if ! s.statsAuthorization(w,r){
		return
	}
	var sta comStats
	sta.RequestCount = statsRequestCount
	sta.ForwardCount = statsForwardCount
	sta.CacheMissCount = statsCacheMissResponse
	sta.CacheSizeUsed = s.rcache.CacheSizeUsed()

	sta.ErrorCountNoname = statsErrorCountNoname
	sta.ErrorCountOverflow = statsErrorCountOverflow
	sta.ErrorNoDataCount = statsNoDataCount

	b, err := json.Marshal(sta)
	if err != nil {
		fmt.Fprintf(w, "%s\n",err.Error())
		return
	}
	fmt.Fprintf(w, "%s\n",string(b))

}

func (s *server) statsAuthorization(w http.ResponseWriter, r *http.Request)bool{
	val,ok := r.Header["Token"]
	if !ok{
		fmt.Fprintf(w, "%s\n","No Authorization")
		return false
	}
	if strings.Compare(val[0], statsAuthToken) != 0 {
		fmt.Fprintf(w, "%s\n","Authorization ERR")
		return false
	}
	return true
}
func (s *server) statsShowCache(w http.ResponseWriter, r *http.Request){
        if ! s.statsAuthorization(w,r){
		return
	}
	var sta domainStats
	//udp
	vars := mux.Vars(r)
	domain := vars["domain"]
	if !strings.HasSuffix(domain, ".") {
		domain = fmt.Sprintf("%s.",domain)
	}
	countUdp,lasttime  := s.rcache.ShowCacheStats(domain,false)
	if countUdp  == 0{
		fmt.Fprintf(w, "%s\n","domain not found")
		return
	}
	sta.LastQueryTime = lasttime
	sta.RequestCount  = countUdp
	b, err := json.Marshal(sta)
	if err != nil {
		fmt.Fprintf(w, "%s\n",err.Error())
		return
	}
	fmt.Fprintf(w, "%s\n",string(b))
}
func (s *server) Statistics(stAddr string,auth string) {
	if stAddr ==""{
		return
	}
	statsAuthToken = auth
	_, err := net.Dial("tcp", stAddr)
       if err == nil {
           glog.Fatalf("statics the addr is used:%s\n",stAddr)
       }
	r := mux.NewRouter()
	r.HandleFunc("/hades/stats", s.statsList).Methods("GET")
	r.HandleFunc("/hades/stats/{domain}", s.statsShowCache).Methods("GET")

	glog.Infof("statistics enabled on :%s", stAddr)
	err = http.ListenAndServe(stAddr, r)
	if err != nil{
		panic(fmt.Sprintf("Failed to start API service:%s", err))
	}

}