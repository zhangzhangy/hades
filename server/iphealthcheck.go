package server

import (
	"strings"
	"encoding/json"
	"time"
	etcd "github.com/coreos/etcd/client"
	"github.com/golang/glog"
)

type apiHadesIpMonitor struct {
	Status        string `json:"status,omitempty"`
	Ports         []string  `json:"ports,omitempty"`
}

func (s *server) SyncHadesHostStatus( ) uint64{
        // get hosts form /hades/monitor/status/

	monitorIps := make(map[string]bool)
	r, err1 := s.backend.Get(s.ipMonitorPath)
	var record apiHadesIpMonitor

	if err1 != nil{
		retStr := err1.Error()
		// if key not fond, keep going
		if !strings.HasPrefix(retStr,"100: Key not found"){
			glog.Infof("Err: %s\n",err1.Error())
			return 0
		}
	}
	watchIdx := r.Index

	for _, n := range r.Node.Nodes{
		if n.Dir {
			continue
		}
		//chck val

		if err := json.Unmarshal([]byte(n.Value), &record); err != nil {
			glog.Infof("Err: %s\n",err.Error())
			return 0
		}
		if record.Status == "UP"{
			ip := n.Key[len(s.ipMonitorPath):]
			monitorIps[ip] = true
		}

	}
	glog.Infof("len of ip monitirs =%d\n",len(monitorIps))
	s.rcache.Lock()
	s.rcache.AvaliableIps = monitorIps
	s.rcache.Unlock()

	return watchIdx
}

func (s *server) doUpdateHostStatus(resp *etcd.Response) {
        //chck val
	var valNew apiHadesIpMonitor
	var valPre apiHadesIpMonitor
	if resp.Node != nil{
		if err := json.Unmarshal([]byte(resp.Node.Value), &valNew); err != nil {
			glog.Infof("Err: %s\n",err.Error())
			return
		}
	}
	if resp.PrevNode != nil{
		if err := json.Unmarshal([]byte(resp.PrevNode.Value), &valPre); err != nil {
			glog.Infof("Err: %s\n",err.Error())
			return
		}
	}
	if valNew.Status != valPre.Status{
		if valNew.Status == "UP"{
			key := resp.Node.Key[len(s.ipMonitorPath):]
			glog.V(2).Infof("UP key :%s\n",key)
			s.rcache.Lock()
			s.rcache.AvaliableIps[key] = true
			s.rcache.Unlock()
		}else if valNew.Status == "DOWN"{
			key := resp.Node.Key[len(s.ipMonitorPath):]
			glog.V(2).Infof("DOWN key :%s\n",key)

			s.rcache.Lock()
			if _, ok:= s.rcache.AvaliableIps[key]; ok{
				delete(s.rcache.AvaliableIps,key)
			}
			s.rcache.Unlock()

		}
	}
}
func (s *server) UpdateHostStatus(resp *etcd.Response) {
      glog.V(2).Infof("UpdateHostStatus: Action =%s Key=%s", resp.Action, resp.Node.Key)
	switch strings.ToLower(resp.Action){
		case "set":
			fallthrough
		case "create":
			s.doUpdateHostStatus(resp)
		case "compareanddelete":
			fallthrough
 		case "delete":
			key := resp.Node.Key[len(s.ipMonitorPath):]
			glog.V(2).Infof("delete key :%s\n",key)
			s.rcache.Lock()
			if _, ok:= s.rcache.AvaliableIps[key]; ok{
				delete(s.rcache.AvaliableIps,key)
			}
			s.rcache.Unlock()

		case "compareandswap":
			fallthrough
		case "update":
			s.doUpdateHostStatus(resp)
		default:
		    	glog.Infof("the action not monitored: Action =%s Key=%s", resp.Action, resp.Node.Key)
	}
}

func(ip *server) HostStatusSync(period time.Duration) {
	for range time.Tick(period) {
		ip.SyncHadesHostStatus()
        }
}