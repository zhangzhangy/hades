
// kube2hades is a bridge between Kubernetes and Hades.  It watches the
// Kubernetes master for changes in Services and manifests them into etcd for
//Hedes to serve as DNS records.
package main

import (
	"encoding/json"
	"fmt"
	"flag"
	"hash/fnv"
	"runtime"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
	"github.com/golang/glog"
	hadesmsg "github.com/ipdcode/hades/msg"
	"gopkg.in/gcfg.v1"
	etcd "github.com/coreos/etcd/client"
	"github.com/ipdcode/hades/utils"

	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	kcache "k8s.io/kubernetes/pkg/client/cache"
	"k8s.io/kubernetes/pkg/client/restclient"
	kclient "k8s.io/kubernetes/pkg/client/unversioned"
	kselector "k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/util/wait"
	"k8s.io/kubernetes/pkg/util/logs"
)

const (
	// Resync period for the kube controller loop.
	resyncPeriod  = 20 * time.Second
	syncAllPeriod = 60 * time.Second
	// A subdomain added to the user specified domain for all services.
	serviceSubdomain = "svc"

	argEtcdMutationTimeout = 10*time.Second

	etcdKeyNotFound = "100: Key not found"
	etcdKeyalReadyExists = "105: Key already exists"

	HadesKubeApiVersion  = "1.0"
)

var(
	gConfig *ConfigOps
	configFile =""
	version   = false
	monitorIpPotrs map[string][]string
)

type GeneralOps struct {
	HadesDomain        string `gcfg:"domain"`
	EtcdServer         string `gcfg:"etcd-server"`
	IpMonitorPath      string `gcfg:"ip-monitor-path"`
	LogDir        	   string `gcfg:"log-dir"`
    	LogLevel      	   string `gcfg:"log-level"`
	LogStdIo      	   string `gcfg:"log-to-stdio"`
}
type Kube2HadesOps struct {
	KubeEnable         string   `gcfg:"kube-enable"`
	KubeMasterURL      string   `gcfg:"kube-master-url"`
}
type HadesApiOps struct {
	ApiAuth            string   `gcfg:"hades-auth"`
	ApiAddr            string     `gcfg:"api-address"`
	ApiEnable          string   `gcfg:"api-enable"`
}

type ConfigOps struct {
       General GeneralOps
       Kube2Hades Kube2HadesOps
       HadesApi   HadesApiOps
}


type nameNamespace struct {
	name      string
	namespace string
}

type kube2hades struct {
	// Etcd client.
	etcdClient *tools.EtcdOps
	// DNS domain name.
	domain string
	// Etcd mutation timeout.
	etcdMutationTimeout time.Duration
	// A cache that contains all the services in the system.
	servicesStore kcache.Store
	endpointsStore kcache.Store

	// Lock for controlling access to headless services.
	mlock sync.Mutex
}

func readConfig(configPath string) (*ConfigOps, error) {

	cfg := new (ConfigOps)
	var config *os.File
	config, err := os.Open(configPath)
	if err != nil {
		glog.Fatalf("Couldn't open cloud provider configuration %s: %#v",
			configPath, err)
	}

	defer config.Close()
	err = gcfg.ReadInto(cfg, config)
	return cfg, err
}

// Removes 'subdomain' from etcd.
func (ks *kube2hades) removeDNS(subdomain string) error {
	glog.V(2).Infof("Removing %s from DNS", subdomain)
	res, err := ks.etcdClient.Get(hadesmsg.Path(subdomain), false, true)
	if err != nil{
		goto errCheck
	}
	err = ks.etcdClient.Delete(res)

errCheck:
	if err != nil {
		if strings.HasPrefix(err.Error(), etcdKeyNotFound){
			return nil
		}else{
			return err
		}
	}
	return err
}

func (ks *kube2hades) writeHadesRecord(subdomain string, data string) error {
	// Set with no TTL, and hope that kubernetes events are accurate.
	res,err := ks.etcdClient.Get(hadesmsg.Path(subdomain), false, true)
	// the key exist
	if err == nil{
		if res.Node.Value == data{
			glog.V(2).Infof(" writeHadesRecord value equal:%s",data)
			return nil
		}else{
			err =   ks.etcdClient.Update(hadesmsg.Path(subdomain), data,res.Node.Value,true )
			goto errCheck
		}
	}
        //set
	if strings.HasPrefix(err.Error(), etcdKeyNotFound){
		err = ks.etcdClient.Set(hadesmsg.Path(subdomain), data)
	}

errCheck:
	if err != nil {
		if strings.HasPrefix(err.Error(), etcdKeyalReadyExists){
			return nil
		}else{
			return err
		}
	}
	return err
}

func (ks *kube2hades) deleteIpMonitorRecord(ip string,) error {
	key := gConfig.General.IpMonitorPath + ip
	res, err := ks.etcdClient.Get(key, false, false)
	if err != nil {
		goto errCheck
	}
	glog.V(2).Infof("deleteIpMonitorRecord :%s",key)
	err = ks.etcdClient.Delete(res)
errCheck:
	if err != nil {
		if strings.HasPrefix(err.Error(), etcdKeyNotFound){
			return nil
		}else{
			return err
		}
	}
	return err
}
func (ks *kube2hades) writeIpMonitorRecord(ip string, ports []string) error {
        var status apiHadesIpMonitor
	status.Status = "UP"
	status.Ports = ports[:]
	b, err := json.Marshal(status)
	if err != nil {
		return err
	}
	recordValue := string(b)
	key := gConfig.General.IpMonitorPath + ip
	glog.V(2).Infof("writeIpMonitorRecord:%s",key)

	res,err := ks.etcdClient.Get(key, false, true)
	// the key exist
	if err == nil{
		glog.V(2).Infof(" writeIpMonitorRecord key:%s exist,val: res.Node.Value:%s",key,res.Node.Value)
		return nil
	}
	//set
	if strings.HasPrefix(err.Error(), etcdKeyNotFound){
		err = ks.etcdClient.Set(key, recordValue)
	}
	if err != nil {
		if strings.HasPrefix(err.Error(), etcdKeyalReadyExists){
			glog.V(4).Infof(" %s \n ",etcdKeyalReadyExists )
			return nil
		}else{
			return err
		}
	}
	return err
}
func getHadesMsg(ip string, port int, dnstype string) *hadesmsg.Service {
	return &hadesmsg.Service{
		Host:     ip,
		Port:     port,
		Priority: 10,
		Weight:   10,
		Ttl:      30,
		Dnstype:  dnstype,
	}
}

func buildPortSegmentString(portName string, portProtocol kapi.Protocol) string {
	if portName == "" {
		// we don't create a random name
		return ""
	}

	if portProtocol == "" {
		glog.Errorf("Port Protocol not set. port segment string cannot be created.")
		return ""
	}

	return fmt.Sprintf("_%s._%s", portName, strings.ToLower(string(portProtocol)))
}

func (ks *kube2hades) generateSRVRecord(subdomain, portSegment, recordName, cName string, portNumber int32) error {
	recordKey := buildDNSNameString(subdomain, portSegment, recordName)
	srv_rec, err := json.Marshal(getHadesMsg(cName, int(portNumber),"SRV"))
	if err != nil {
		return err
	}
	glog.Infof(" srv recordKey =%s\n",recordKey)
	if err := ks.writeHadesRecord(recordKey, string(srv_rec)); err != nil {
		return err
	}
	return nil
}

func (ks *kube2hades) generateOneRecordForPortalService(subdomain string, ip string, service *kapi.Service) error {

	b, err := json.Marshal(getHadesMsg(ip, 0,"A"))
	if err != nil {
		return err
	}
	recordValue := string(b)
	recordLabel := getHash(recordValue)
	recordKey := buildDNSNameString(subdomain, recordLabel)

	glog.V(2).Infof("Setting DNS record: %v -> %q, with recordKey: %v\n", subdomain, recordValue, recordKey)
	if err := ks.writeHadesRecord(recordKey, recordValue); err != nil {
		return err
	}
	var ports []string
	for i := range service.Spec.Ports {
		port := &service.Spec.Ports[i]
		ports = append(ports, fmt.Sprintf("%d", port.Port) )
	}
	ks.writeIpMonitorRecord(ip,ports)
	return nil
}
func (ks *kube2hades) generateRecordsForPortalService(subdomain string, service *kapi.Service) error {

	for _, ip := range(service.Spec.ExternalIPs){
		ks.generateOneRecordForPortalService(subdomain,ip,service)
	}
	return nil
}

func (ks *kube2hades)IsServiceVIPSet(service *kapi.Service) bool{
	if len(service.Spec.ExternalIPs) == 0  || service.Spec.ExternalIPs[0] == ""{
		return false
	}
	return true
}

func (ks *kube2hades)IsServiceVIPDiff(oldsvc *kapi.Service,newsvc *kapi.Service) bool{
	i := len(oldsvc.Spec.ExternalIPs)
	j := len(newsvc.Spec.ExternalIPs)
	if  i != j {
		return true
	}
	// no vip
	if i ==0{
		return false
	}
	if reflect.DeepEqual(oldsvc.Spec.ExternalIPs, newsvc.Spec.ExternalIPs){
		return false
	}
	return true
}

func (ks *kube2hades) isServiceSrv(service *kapi.Service) bool {
	return service.Spec.ClusterIP == "None"
}
func (ks *kube2hades) addDNS(subdomain string, service *kapi.Service) error {
	// if ClusterVIP is not set, a DNS entry should not be created
	if !ks.IsServiceVIPSet(service) {
		glog.V(2).Info("ignore the svc for cluster LB VIP is nil : %s", service.Name)
		return nil
	}
	// SRV
	if  ks.isServiceSrv(service){
		return nil
	}
	return ks.generateRecordsForPortalService(subdomain, service)
}

func buildDNSNameString(labels ...string) string {
	var res string
	for _, label := range labels {
		if res == "" {
			res = label
		} else {
			res = fmt.Sprintf("%s.%s", label, res)
		}
	}
	return res
}

// Returns a cache.ListWatch that gets all changes to services.
func createServiceLW(kubeClient *kclient.Client) *kcache.ListWatch {
	return kcache.NewListWatchFromClient(kubeClient, "services", kapi.NamespaceAll, kselector.Everything())
}
func createEndpointsLW(kubeClient *kclient.Client) *kcache.ListWatch {
	return kcache.NewListWatchFromClient(kubeClient, "endpoints", kapi.NamespaceAll, kselector.Everything())
}

func (ks *kube2hades) newService(obj interface{}) {
	if s, ok := obj.(*kapi.Service); ok {
		name := buildDNSNameString(ks.domain, serviceSubdomain, s.Namespace, s.Name)
		ks.addDNS(name, s)
	}
}
func (ks *kube2hades)checkEndpointUpdate(objNew interface{},objOld interface{}) bool {
	olde, ok1 := objOld.(*kapi.Endpoints)
	newe, ok2 := objNew.(*kapi.Endpoints)
	if ok1 && ok2{
		if( olde.Name != newe.Name || olde.Namespace != newe.Namespace || len(olde.Subsets) != len(newe.Subsets)) {
			return true
		}
		return false
	}
	return false
}

func (ks *kube2hades) handleEndpointAdd(obj interface{}) {
	if e, ok := obj.(*kapi.Endpoints); ok {
		name := buildDNSNameString(ks.domain, serviceSubdomain, e.Namespace, e.Name)
		ks.addDNSUsingEndpoints(name, e)
	}
}
func (ks *kube2hades) getServiceFromEndpoints(e *kapi.Endpoints) (*kapi.Service, error) {
	key, err := kcache.MetaNamespaceKeyFunc(e)
	if err != nil {
		return nil, err
	}
	obj, exists, err := ks.servicesStore.GetByKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get service object from services store - %v", err)
	}
	if !exists {
		glog.V(1).Infof("could not find service for endpoint %q in namespace %q", e.Name, e.Namespace)
		return nil, nil
	}
	if svc, ok := obj.(*kapi.Service); ok {
		return svc, nil
	}
	return nil, fmt.Errorf("got a non service object in services store %v", obj)
}

func (ks *kube2hades) addDNSUsingEndpoints(subdomain string, e *kapi.Endpoints) error {
	ks.mlock.Lock()
	defer ks.mlock.Unlock()
	svc, err := ks.getServiceFromEndpoints(e)
	if err != nil {
		return err
	}
	if svc == nil || !ks.isServiceSrv(svc) {
		// No headless service found corresponding to endpoints object.
		return nil
	}
	// Remove existing DNS entry.
	if err := ks.removeDNS(subdomain); err != nil {
		return err
	}
	return ks.generateRecordsForHeadlessService(subdomain, e, svc)
}

func (ks *kube2hades) generateRecordsForHeadlessService(subdomain string, e *kapi.Endpoints, svc *kapi.Service) error {
	for idx := range e.Subsets {
		for subIdx := range e.Subsets[idx].Addresses {
			endpointIP := e.Subsets[idx].Addresses[subIdx].IP
			b, err := json.Marshal(getHadesMsg(endpointIP, 0,"A"))
			if err != nil {
				return err
			}
			recordValue := string(b)
			recordLabel := getHash(recordValue)

			recordKey := buildDNSNameString(subdomain, recordLabel)

			glog.V(2).Infof("Setting DNS record: %v -> %q\n", recordKey, recordValue)
			if err := ks.writeHadesRecord(recordKey, recordValue); err != nil {
				return err
			}

			var ports []string

			for portIdx := range e.Subsets[idx].Ports {
				endpointPort := &e.Subsets[idx].Ports[portIdx]
				portSegment := buildPortSegmentString(endpointPort.Name, endpointPort.Protocol)
				if portSegment != "" {
					err := ks.generateSRVRecord(subdomain, portSegment, recordLabel, recordKey, endpointPort.Port)
					if err != nil {
						return err
					}
					ports = append(ports, fmt.Sprintf("%d",endpointPort.Port) )
				}
			}
			// write monitor
			ks.writeIpMonitorRecord(endpointIP,ports)
		}
	}

	return nil
}
func (ks *kube2hades) removeService(obj interface{}) {
	if s, ok := obj.(*kapi.Service); ok {
		// no vip return
		if ! ks.IsServiceVIPSet(s){
			glog.V(2).Info("ignore the svc for cluster LB VIP is nil : %s", s.Name)
			return
		}
		name := buildDNSNameString(ks.domain, serviceSubdomain, s.Namespace, s.Name)
		err := ks.removeDNS(name)
		if err != nil {
			glog.Infof("removeService err: %s", err.Error())
		}
		for _,ip := range(s.Spec.ExternalIPs){
			err = ks.deleteIpMonitorRecord(ip)
			if err != nil {
				glog.Infof("deleteIpMonitorRecord err: %s", err.Error())
			}
		}

	}
}

func (ks *kube2hades) updateService(oldObj, newObj interface{}) {
	oldsvc, ok1 := oldObj.(*kapi.Service)
	newsvc, ok2 := newObj.(*kapi.Service)
	if ok1 && ok2{
		// name or namespace or ip change
		if oldsvc.Name != newsvc.Name || oldsvc.Namespace != newsvc.Namespace || ks.IsServiceVIPDiff(oldsvc, newsvc) {
			ks.removeService(oldObj)
			ks.newService(newObj)
			return
		}
		glog.V(4).Infof("ignore updateService this time \n")
	}
}

func newEtcdClient(etcdServer string) *tools.EtcdOps {
	etcdcli := tools.EtcdOps{}
	err := etcdcli.InitEtcd(strings.Split(etcdServer,","))
	if err != nil{
		glog.Fatalf("Failed to create etcd client - %v", err)
	}
 	return &etcdcli
}

func newKubeClient() (*kclient.Client, error) {

	config := &restclient.Config{
		Host:          gConfig.Kube2Hades.KubeMasterURL,
		ContentConfig: restclient.ContentConfig{GroupVersion: &unversioned.GroupVersion{Version: "v1"}},
	}

	glog.Infof("Using %s for kubernetes master", config.Host)
	glog.Infof("Using kubernetes API %v", config.GroupVersion)
	return kclient.New(config)
}

func watchForServices(kubeClient *kclient.Client, ks *kube2hades) kcache.Store {
	serviceStore, serviceController := kcache.NewInformer(
		createServiceLW(kubeClient),
		&kapi.Service{},
		resyncPeriod,
		kcache.ResourceEventHandlerFuncs{
			AddFunc:    ks.newService,
			DeleteFunc: ks.removeService,
			UpdateFunc: ks.updateService,
		},
	)
	go serviceController.Run(wait.NeverStop)
	return serviceStore
}

func watchEndpoints(kubeClient *kclient.Client, ks *kube2hades) kcache.Store {
	eStore, eController := kcache.NewInformer(
		createEndpointsLW(kubeClient),
		&kapi.Endpoints{},
		resyncPeriod,
		kcache.ResourceEventHandlerFuncs{
			AddFunc: ks.handleEndpointAdd,
			UpdateFunc: func(oldObj, newObj interface{}) {
				if ks.checkEndpointUpdate(newObj, oldObj){
					ks.handleEndpointAdd(newObj)
				}

			},
		},
	)

	go eController.Run(wait.NeverStop)
	return eStore
}

func getHash(text string) string {
	h := fnv.New32a()
	h.Write([]byte(text))
	return fmt.Sprintf("%x", h.Sum32())
}

func checkConfigOps(){
	// domain
	if gConfig.General.HadesDomain == ""{
		gConfig.General.HadesDomain ="hades.local."
	}
	// ip monitor path
	if gConfig.General.IpMonitorPath == ""{
		gConfig.General.IpMonitorPath = "/hades/monitor/status/"
	}

	if !strings.HasSuffix(gConfig.General.HadesDomain, ".") {
		gConfig.General.HadesDomain = fmt.Sprintf("%s.", gConfig.General.HadesDomain)
	}
	if !strings.HasSuffix(gConfig.General.IpMonitorPath, "/") {
		gConfig.General.IpMonitorPath = fmt.Sprintf("%s/", gConfig.General.IpMonitorPath)
	}
	//etcd
        if gConfig.General.EtcdServer == ""{
		glog.Fatal("EtcdServer is nil, check config file : ",configFile)
	}

	// kube
	if strings.ToUpper(gConfig.Kube2Hades.KubeEnable) == "YES"{
		gConfig.Kube2Hades.KubeEnable = "YES"
		if gConfig.Kube2Hades.KubeMasterURL == ""{
			glog.Fatal("KubeMasterURL is nil, check config file : ",configFile)
		}
	}
	// api
	if strings.ToUpper(gConfig.HadesApi.ApiEnable) == "YES"{
		gConfig.HadesApi.ApiEnable = "YES"
		if gConfig.HadesApi.ApiAddr == ""{
			glog.Fatal("ApiAddr is nil, check config file : ",configFile)
		}
		if gConfig.HadesApi.ApiAuth == ""{
			glog.Fatal("ApiAuth is nil, check config file :",configFile)
		}
	}

	// nor
	if gConfig.HadesApi.ApiEnable != "YES" && gConfig.Kube2Hades.KubeEnable != "YES" {
		glog.Fatal("both kube-enable and api-enable are nil , check config file : ",configFile)
	}
}
func (ks *kube2hades) getServicesSRVRecords(s *kapi.Service,svcMap map[string]string,ipPorts map[string][]string) {
	// get endpoint
	var e *kapi.Endpoints = nil
	for _, m := range ks.endpointsStore.List() {
		ep := m.(*kapi.Endpoints)
		if s.Name == ep.Name && s.Namespace == ep.Namespace {
			e = ep
			break
		}
	}
	if e == nil{
		return
	}
	subdomain := buildDNSNameString(ks.domain, serviceSubdomain, e.Namespace, e.Name)

	// get the key val
	for idx := range e.Subsets {
		for subIdx := range e.Subsets[idx].Addresses {
			endpointIP := e.Subsets[idx].Addresses[subIdx].IP
			b, err := json.Marshal(getHadesMsg(endpointIP, 0,"A"))
			if err != nil {
				return
			}
			recordValue := string(b)
			recordLabel := getHash(recordValue)
			recordKey := buildDNSNameString(subdomain, recordLabel)

			svcMap[hadesmsg.Path(recordKey)] = recordValue

		        //srv
			for portIdx := range e.Subsets[idx].Ports {
				endpointPort := &e.Subsets[idx].Ports[portIdx]
				portSegment := buildPortSegmentString(endpointPort.Name, endpointPort.Protocol)
				if portSegment != "" {
					recordKeyReal := buildDNSNameString(subdomain, portSegment, recordLabel)
					srv_rec, err := json.Marshal(getHadesMsg(recordKey, int(endpointPort.Port),"SRV"))
					if err != nil {
						return
					}
					svcMap[hadesmsg.Path(recordKeyReal)] = string(srv_rec)
					ipPorts[endpointIP] = append(ipPorts[endpointIP],fmt.Sprintf("%d",endpointPort.Port) )
				}
			}
		}
	}
	return
}
func (ks *kube2hades) getServicesFromKube() (map[string]string,map[string][]string, bool) {
	svcMap := make(map[string]string)
	ipPorts := make(map[string][]string)
	services := ks.servicesStore.List()

	if len(services) ==0{
		glog.Infof("getServices : list no svcs found\n")
		return svcMap , ipPorts,false
	}
	for _, s := range services {
		if s, ok := s.(*kapi.Service); ok {

			// SDR record
			if  ks.isServiceSrv(s) {
				ks.getServicesSRVRecords(s,svcMap,ipPorts)
				continue
			}

			if !ks.IsServiceVIPSet(s){
				glog.V(2).Info("ignore the svc for cluster LB VIP is nil : %s", s.Name)
				continue
			}
			for _, ip := range(s.Spec.ExternalIPs){
				b, err := json.Marshal(getHadesMsg(ip , 0,"A"))
				if err != nil {
					continue
				}
				recordValue := string(b)
				recordLabel := getHash(recordValue)
				recordKey := buildDNSNameString(ks.domain, serviceSubdomain, s.Namespace, s.Name, recordLabel)
				svcMap[hadesmsg.Path(recordKey)] = recordValue

				// get ports
				for i := range s.Spec.Ports {
					port := &s.Spec.Ports[i]
					ipPorts[ip] = append(ipPorts[ip],fmt.Sprintf("%d", port.Port) )
				}
			}

	       }
		continue
	}
	return svcMap, ipPorts,true
}

func (ks *kube2hades) kubeLoopNodes(n *etcd.Nodes,sx map[string]string, hosts map[string]bool ) error{
	var record apiHadesRecord

	for _, n := range *n {
		if n.Dir {
			err := ks.kubeLoopNodes(&n.Nodes, sx, hosts)
			if err != nil {
				return err
			}
			continue
		}
		if err := json.Unmarshal([]byte(n.Value), &record); err != nil {
			return  err
		}

		switch record.Dnstype{
		case "A":
			sx[n.Key] = n.Value
			hosts[record.Host]  = true
		// no use etcd get cannot find _tcp
		case "SRV":
			sx[n.Key] = n.Value
		default:
			continue
		}
	}
	return  nil
}
func (ks *kube2hades) getServicesFromHades(name string,sx map[string]string, hosts map[string]bool) error {
	subdomain := buildDNSNameString(name)

	r, err := ks.etcdClient.Get(hadesmsg.Path(subdomain), false,true)
	if err != nil {
		return err
	}
	switch {
	case r.Node.Dir:
		return ks.kubeLoopNodes(&r.Node.Nodes,sx,hosts)
	default:
		return ks.kubeLoopNodes(&etcd.Nodes{r.Node},sx,hosts)
	}
}

func (ks *kube2hades) syncKube2Hades() {
	glog.V(2).Info("Begin syncKube2Hades...")
        var kubeServices map[string]string
	var ok bool
	kubeServices, monitorIpPotrs,ok = ks.getServicesFromKube()
	if ok != true{
		return
	}
	svcHades := make(map[string]string)
	hostHades := make(map[string]bool)
	// just get svc.
	err := ks.getServicesFromHades(serviceSubdomain + "."+ gConfig.General.HadesDomain ,svcHades,hostHades)
	if err != nil{
		retStr := err.Error()
		// if key not fond, keep going
		if !strings.HasPrefix(retStr,etcdKeyNotFound){
			glog.Infof("Err: %s\n",err.Error())
			return
		}
	}

	for key,val := range kubeServices {
		glog.V(4).Infof("svc in Kube:: key :%s  val =%s\n", key,val)
		valHades, exists := svcHades[key]
		if exists{
			if strings.Compare(valHades, val) != 0 {
				glog.V(3).Infof("key =%s  kubeval =%s hadesVal =%s\n", key,val,valHades)
				ks.etcdClient.Update(key,val,valHades,true)
			}
			continue
		}
		//we add new one
		ks.etcdClient.Set(key,val)
	}
	// Remove services missing from the update.
	for name,valHades := range svcHades {
		glog.V(4).Infof("svc in Hades:: key :%s  val =%s\n",name,valHades)
		_, exists := kubeServices[name]
		if !exists{
			glog.V(3).Infof("del from hades key :%s  val =%s\n", name,valHades)
			ks.etcdClient.DoDelete(name,valHades)
		}
	}
}

func (ks *kube2hades) syncHadesHostStatus() {
	glog.V(2).Info("Begin syncHadesHostStatus...")
	// just get svc + user define
	svcHades := make(map[string]string)
	hostsHades := make(map[string]bool)
	err := ks.getServicesFromHades(gConfig.General.HadesDomain ,svcHades,hostsHades)
	if err != nil{
		retStr := err.Error()
		// if key not fond, keep going
		if !strings.HasPrefix(retStr,etcdKeyNotFound){
			glog.Infof("Err: %s\n",err.Error())
			return
		}
	}
        // get hosts form /hades/monitor/status/
	monitorIps := make(map[string]bool)
	r, err1 := ks.etcdClient.Get(gConfig.General.IpMonitorPath, false,true)
	if err1 != nil{
		retStr := err1.Error()
		// if key not fond, keep going
		if !strings.HasPrefix(retStr,etcdKeyNotFound){
			glog.Infof("Err: %s\n",err1.Error())
			return
		}
	}
	if err1 == nil{
		for _, n := range r.Node.Nodes{
			if n.Dir {
				continue
			}
			ip := n.Key[len(gConfig.General.IpMonitorPath):]
			monitorIps[ip] = true
		}

	}

	//update the diffs
	for key,_ := range hostsHades {
		glog.V(4).Infof("svcHosts key: %s\n",key)

		_, exists := monitorIps[key]
		if !exists{
			var status apiHadesIpMonitor
			status.Status = "UP"

			// check ports
			_, exists = monitorIpPotrs[key]
			if exists{
				status.Ports = monitorIpPotrs[key][:]
			}

			b, err := json.Marshal(status)
			if err != nil {
				glog.Infof("json.Marshal err: %s\n",err.Error())
				return
			}
			recordValue := string(b)
			ks.etcdClient.Set(gConfig.General.IpMonitorPath + key,recordValue)
		}
	}

	for key,_ := range monitorIps {
		glog.V(4).Infof("monitorIps key: %s\n",key)
		_, exists := hostsHades[key]
		if !exists{
			ks.etcdClient.DeleteRaw(gConfig.General.IpMonitorPath + key)
		}
	}

}
func (ks *kube2hades) svcSyncLoop(period time.Duration) {
	for range time.Tick(period) {
		glog.Infof("svcSyncLoop \n")
		ks.syncKube2Hades()
		ks.syncHadesHostStatus()
        }
}

func init() {
	flag.StringVar(&configFile, "config-file", "/etc/hades/hades-api.conf", "read config from the file")
	flag.BoolVar(&version, "version",false, "Print version information and quit")
	flag.Parse()
	var e error; if gConfig, e = readConfig(configFile); e != nil {
		glog.Fatal("Read config file error, due to", e.Error())
		os.Exit(1)
	}
	flag.Lookup("log_dir").Value.Set(gConfig.General.LogDir)
	flag.Lookup("v").Value.Set(gConfig.General.LogLevel)
	flag.Lookup("logtostderr").Value.Set(gConfig.General.LogStdIo)

}
func main() {
	if version{
		fmt.Printf("%s\n",HadesKubeApiVersion)
		return
	}
	runtime.GOMAXPROCS(runtime.NumCPU())
	logs.InitLogs()
	defer logs.FlushLogs()

	checkConfigOps()

	ks := kube2hades{
		domain:              gConfig.General.HadesDomain,
		etcdMutationTimeout: argEtcdMutationTimeout,
	}

	ks.etcdClient= newEtcdClient(gConfig.General.EtcdServer)

	if gConfig.Kube2Hades.KubeEnable == "YES" {
		glog.Infof("kubernetes serverce to dns enable ")
		kubeClient, err := newKubeClient()
		if err != nil {
			glog.Fatalf("Failed to create a kubernetes client: %v", err)
		}
		ks.servicesStore = watchForServices(kubeClient, &ks)
		ks.endpointsStore = watchEndpoints(kubeClient, &ks)

		go ks.svcSyncLoop(syncAllPeriod)
        }
	if gConfig.HadesApi.ApiEnable == "YES" {
		glog.Infof("hedes  dns api enable ")
		RunApi(ks.etcdClient, gConfig.HadesApi.ApiAddr ,gConfig.General.HadesDomain,gConfig.HadesApi.ApiAuth, gConfig.General.IpMonitorPath )
	}
	// wait here
	select{}

}
