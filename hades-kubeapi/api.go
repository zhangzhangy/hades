package main

import (
	"fmt"
	"net/http"
	"io/ioutil"
	"encoding/json"
	"hash/fnv"
	"net"
	"strings"
	"time"
	hadesmsg "github.com/ipdcode/hades/msg"
	etcd "github.com/coreos/etcd/client"
	"github.com/golang/glog"
	"github.com/ipdcode/hades/utils"
	"github.com/gorilla/mux"
)

const (
	// A subdomain added to the user specified domain for user definded.
	userSubdomain = "user"
	svcSubdomain = "svc"

	noDomainName = "ERR, no domain name "
	errDomainContainDot = "ERR,  domain name cant not contain dot "
	noFindDomainName = "ERR, no find  domain name "
	noFindDomainIp = "ERR, no find  domain ip "
	errDeleteDomainName = "ERR, delete domain name error"
	errDeleteK8sSvc = "ERR, can not del k8s svc "
	errSetDomainName    = "ERR, set domain name error "
	errSetDomainNameExists    = "ERR, set domain name error  domain exists "
	errPutTooManyItems   = "ERR, put just support  one update one time"
	errSetAliasNameExists    = "ERR, set domain name error  alias exists "
	noFindAliasName    = "ERR, not find   alias name "
	noMatchAliasName    = "ERR, alias name and domain not match "
        errUpdateDomainName    = "ERR, update domain name error "
	errGetDomainName    = "ERR, get domain name error "
	noAuthorization = "ERR, no Authorization "
	errAuthorization = "ERR, Authorization error "
	noDomainIps = "ERR, no domain ips "
	notIpAddr = "ERR, it is not  IP addr "
	notSupportIpv6 = "ERR, ipv6 tbd "
	notSupportOpsType = "ERR,type not support "
	noOpsType = "ERR, no type offered "
	errBodyUpdate = "ERR, no body update "
	apiSucess  = "OK"
)

type apiService struct {
	AliasDomain string `json:"alias-domain,omitempty"`
	OpsType string `json:"type,omitempty"`
	DomainIps []string `json:"ips,omitempty"`
	DomainAlias  string `json:"alias,omitempty"`
	UpdateMap   map[string]string  `json:"update,omitempty"`
	NsHost string `json:"nsHost,omitempty"`
	MailHost string `json:"mailHost,omitempty"`
	MailPriority int `json:"mailPriority,omitempty"`
	TxtRecord    string `json:"text,omitempty"`
}

// a record to etcd
type apiHadesRecord struct {
	Host    string `json:"host,omitempty"`
	Dnstype string  `json:"type,omitempty"`
	Ttl      uint32 `json:"ttl,omitempty"`
	Mail    bool `json:"mail,omitempty"`
	MailPriority int  `json:"priority,omitempty"`

	Text string  `json:"text,omitempty"`


}
// a record to etcd for ip monitor
type apiHadesIpMonitor struct {
	Status        string `json:"status,omitempty"`
	Ports         []string  `json:"ports,omitempty"`
}

type hadesApi struct {
	etcdClient   *tools.EtcdOps
	domain  string
	auth  string
	ipMonitorPath string
}
var hapi hadesApi = hadesApi{}


func (a *hadesApi)getHashIp(text string) string {
	h := fnv.New32a()
	h.Write([]byte(text))
	return fmt.Sprintf("%x", h.Sum32())
}

func (a *hadesApi)buildDNSNameString(labels ...string) string {
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

func (a *hadesApi) setHadesRecordHost(name string, ipaddr string,dnsType string) string {
        var svc apiHadesRecord
	svc.Host = ipaddr
	svc.Ttl  = 30
	svc.Dnstype = dnsType
	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s\n", err.Error())
		return errSetDomainName
	}
	recordValue := string(b)
	glog.V(2).Infof("setHadesRecordHost:%s",hadesmsg.Path(name))

	err = a.etcdClient.Set(hadesmsg.Path(name), recordValue)
	time.Sleep(20*time.Microsecond)

	if err != nil {
		retStr := err.Error()
		if strings.HasPrefix(retStr,etcdKeyalReadyExists){
			glog.Infof("Err: %s\n",retStr)
			return errSetDomainNameExists + ipaddr
		}
		glog.Infof("Err: %s\n",retStr)
		return errSetDomainName
	}else{
		return  apiSucess
	}
}

func (a *hadesApi) setHadesRecordMail(name string, host string,priority int ,dnsType string) string {
        var svc apiHadesRecord
	svc.Host = host
	svc.Dnstype = dnsType
	svc.Mail    = true
	svc.MailPriority = priority
	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s\n", err.Error())
		return errSetDomainName
	}
	recordValue := string(b)
	glog.V(2).Infof("setHadesRecordHost:%s",hadesmsg.Path(name))

	err = a.etcdClient.Set(hadesmsg.Path(name), recordValue)

	if err != nil {
		retStr := err.Error()
		if strings.HasPrefix(retStr,etcdKeyalReadyExists){
			glog.Infof("Err: %s\n",retStr)
			return errSetDomainNameExists
		}
		glog.Infof("Err: %s\n",retStr)
		return errSetDomainName
	}else{
		return  apiSucess
	}
}

func (a *hadesApi) setHadesRecordText(name string, text string,dnsType string) string {
        var svc apiHadesRecord
	svc.Text = text
	svc.Dnstype = dnsType

	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s\n", err.Error())
		return errSetDomainName
	}
	recordValue := string(b)
	glog.V(2).Infof("setHadesRecordHost:%s",hadesmsg.Path(name))

	err = a.etcdClient.Set(hadesmsg.Path(name), recordValue)

	if err != nil {
		retStr := err.Error()
		if strings.HasPrefix(retStr,etcdKeyalReadyExists){
			glog.Infof("Err: %s\n",retStr)
			return errSetDomainNameExists
		}
		glog.Infof("Err: %s\n",retStr)
		return errSetDomainName
	}else{
		return  apiSucess
	}
}

func (a *hadesApi) updateHadesRecord(name string, preVal string,newVal string, dnsType string) string {
        var svc apiHadesRecord
	svc.Host = preVal
	svc.Dnstype = dnsType
	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s\n", err.Error())
		return errUpdateDomainName
	}
	recordPre := string(b)

	svc.Host = newVal
	svc.Dnstype = dnsType
	b, err = json.Marshal(svc)
	if err != nil {
		glog.Infof("%s\n", err.Error())
		return errUpdateDomainName
	}
	recordNew := string(b)

        glog.V(2).Infof("updateHadesRecord :%s",hadesmsg.Path(name))

	err = a.etcdClient.Update(hadesmsg.Path(name), recordNew, recordPre, true)

	if err != nil {
		glog.Infof("%s\n", err.Error())
		return errUpdateDomainName
	}else{
		return apiSucess
	}
}
func (a *hadesApi) deleteHadesRecord(name string,) string {
	res, err := a.etcdClient.Get(hadesmsg.Path(name), false, true)
	if err != nil {
		glog.Infof("%s\n", err.Error())
		return noFindDomainName
	}
	glog.V(2).Infof("deleteHadesRecord :%s",hadesmsg.Path(name))

	err = a.etcdClient.Delete(res)
	time.Sleep(20*time.Microsecond)


	if err != nil {
		glog.Infof("%s\n", err.Error())
		return errDeleteDomainName
	}
	return apiSucess
}

func (a *hadesApi) deleteIpMonitorRecord(ip string,) error {
	key := a.ipMonitorPath + ip
	res, err := a.etcdClient.Get(key, false, false)
	if err != nil {
		if !strings.HasPrefix(err.Error(),etcdKeyNotFound){
			return err
		}else{
			return nil
		}

	}
	glog.V(2).Infof("deleteIpMonitorRecord :%s",key)

	err = a.etcdClient.Delete(res)
	time.Sleep(20*time.Microsecond)
	return err
}

func (a *hadesApi)  writeIpMonitorRecord(ip string) error {
        var status apiHadesIpMonitor
	status.Status = "UP"
	b, err := json.Marshal(status)
	if err != nil {
		return err
	}
	recordValue := string(b)
	key := a.ipMonitorPath  + ip
	glog.V(2).Infof("writeIpMonitorRecord:%s",key)

	res,err := a.etcdClient.Get(key, false, true)
	// the key exist
	if err == nil{
		glog.V(2).Infof(" writeIpMonitorRecord key:%s exist,val: res.Node.Value:%s",res.Node.Value)
		return nil
	}

	if strings.HasPrefix(err.Error(), etcdKeyNotFound){
		err = a.etcdClient.Set(key, recordValue)
	}
	time.Sleep(20*time.Microsecond)

	return err
}

func (a *hadesApi) apiLoopNodes(n *etcd.Nodes,sx map[string]apiService) (err error) {
	var record apiHadesRecord

	for _, n := range *n {
		if n.Dir {
			 err := a.apiLoopNodes(&n.Nodes, sx)
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
			key := a.getDomainNameFromKeyA(n.Key)
			if svc, ok := sx[key]; ok {
				svc.DomainIps = append(svc.DomainIps,record.Host )
				sx[key] = svc
				continue
		 	}
			serv := new(apiService)
			serv.DomainIps = append(serv.DomainIps,record.Host )
			serv.OpsType   = "A"
			sx[key] = *serv
		case "CNAME":
			key := a.getDomainNameFromKey(n.Key)
			serv := new(apiService)
			serv.OpsType   = "CNAME"
			serv.AliasDomain = record.Host
			sx[key] = *serv
		case "NS":
			key := a.getDomainNameFromKey(n.Key)
			serv := new(apiService)
			serv.OpsType   = "NS"
			serv.NsHost = record.Host
			sx[key] = *serv

		case "MX":
			key := a.getDomainNameFromKey(n.Key)
			serv := new(apiService)
			serv.OpsType   = "MX"
			serv.MailHost = record.Host
			serv.MailPriority = record.MailPriority
			sx[key] = *serv

		case "TXT":
			key := a.getDomainNameFromKey(n.Key)
			serv := new(apiService)
			serv.OpsType   = "TXT"
			serv.TxtRecord = record.Text
			sx[key] = *serv

		default:
			glog.Infof("unknowm type: %s\n",record.Dnstype)
			continue
		}
	}
	return  nil
}

func (a *hadesApi)getDomainNameFromKey(key string) string{
	keys := strings.Split(key,"/")
	domLen := len(keys)-1
	for i, j := 0,domLen; i < j; i, j = i+1, j-1 {
		keys[i], keys[j] = keys[j], keys[i]
	}
	domainKey := strings.Join(keys[:domLen-1], ".")
	return domainKey
}

func (a *hadesApi)getDomainNameFromKeyA(key string) string{
	keys := strings.Split(key,"/")
	domLen := len(keys)-1
	for i, j := 0,domLen; i < j; i, j = i+1, j-1 {
		keys[i], keys[j] = keys[j], keys[i]
	}
	domainKey := strings.Join(keys[1:domLen-1], ".") // ingoore the first
	return domainKey
}

func (a *hadesApi)doGetHadesRecords(n string,sx map[string]apiService) error {
	r, err := a.etcdClient.Get(hadesmsg.Path(n), true,true)
	if err != nil {
		return err
	}
	switch {
	case r.Node.Dir:
		return a.apiLoopNodes(&r.Node.Nodes,sx)
	default:
		return a.apiLoopNodes(&etcd.Nodes{r.Node},sx)
	}
}

func (a *hadesApi) getHadesRecords(name string,opstype string, sx map[string]apiService) error {

	n :=""
	if name !=""{
		n = a.buildDNSNameString(a.domain,name)
		return a.doGetHadesRecords(n, sx)

	}else{  // show all
		switch strings.ToUpper(opstype){
		case "NS": n = a.buildDNSNameString(a.domain,"ns.dns")
		case "MX": n = a.buildDNSNameString(a.domain,"mail")
		case "TXT": n = a.buildDNSNameString(a.domain,"txt")
		default :  n = a.buildDNSNameString(a.domain)
		}
		return a.doGetHadesRecords(n, sx)
	}
}

func (a *hadesApi)processTypeAPost(s *apiService,domain string )string{
	if len(s.DomainIps) == 0{
		return noDomainIps
	}
	for _, ipaddr := range s.DomainIps{
		ip := net.ParseIP(ipaddr)
		switch {
		case ip == nil:
			return notIpAddr
		case ip.To4() != nil:
			name := a.buildDNSNameString(a.domain,domain,a.getHashIp(ipaddr))
			ret := a.setHadesRecordHost(name,ipaddr,"A")
			if ret != apiSucess{
				return ret
			}
			a.writeIpMonitorRecord(ipaddr)
		default:
			return notSupportIpv6
		}
	}
	return apiSucess
}

func (a *hadesApi)processTypeADelete(s *apiService,domain string )string{

	name :=""
	ret :=""
	// no ips del all
	if len(s.DomainIps) == 0{
		name = a.buildDNSNameString(a.domain,domain)
		ret = a.deleteHadesRecord(name)
		return ret
	}
	name = a.buildDNSNameString(a.domain,domain)
	_, err := a.etcdClient.Get(hadesmsg.Path(name), false, true)
	if err != nil {
		glog.Infof("%s\n", err.Error())
		return noFindDomainName
	}

	for _, ipaddr := range s.DomainIps{
		ip := net.ParseIP(ipaddr)
		switch {
		case ip == nil:
			return notIpAddr
		case ip.To4() != nil:
			name = a.buildDNSNameString(a.domain,domain,a.getHashIp(ipaddr))
			ret = a.deleteHadesRecord(name)
			if ret != apiSucess{
				return noFindDomainIp
			}
			a.deleteIpMonitorRecord(ipaddr)

		default:
			return notSupportIpv6
		}
	}
	if ret == apiSucess{
		svc := make(map[string]apiService)
		err := a.getHadesRecords(domain,"A", svc)
		if len(svc) == 0 && err == nil{
			name = a.buildDNSNameString(a.domain,domain)
			a.deleteHadesRecord(name)
		}
	}
	return apiSucess
}

func (a *hadesApi )processTypeAPut(s *apiService, domain string)string {
	if len(s.UpdateMap) != 1{
		return errPutTooManyItems
	}
	for key, val := range s.UpdateMap {
		ipPre := net.ParseIP(key)
		ipNew := net.ParseIP(val)

		if ipPre.To4() != nil && ipNew.To4() != nil {
			// check val exist
			name := a.buildDNSNameString(a.domain, domain, a.getHashIp(val))
			_, err := a.etcdClient.Get(hadesmsg.Path(name), true,true)
			if err == nil {
				return errSetDomainNameExists + val
			}
			// check key exist
			name = a.buildDNSNameString(a.domain, domain)
			_, err = a.etcdClient.Get(hadesmsg.Path(name), true,true)
			if err != nil {
				return noFindDomainName + domain
			}
			name = a.buildDNSNameString(a.domain, domain, a.getHashIp(key))
			_, err = a.etcdClient.Get(hadesmsg.Path(name), true,true)
			if err != nil {
				return noFindDomainIp + key
			}

			//del old
			name = a.buildDNSNameString(a.domain, domain, a.getHashIp(key))
			ret := a.deleteHadesRecord(name)
			if ret != apiSucess {
				return ret
			}
			a.deleteIpMonitorRecord(key)
                        // add new
			name = a.buildDNSNameString(a.domain, domain, a.getHashIp(val))
			ret = a.setHadesRecordHost(name, val,"A")
			//
			if ret != apiSucess {
				return ret
			}

			a.writeIpMonitorRecord(val)

		} else {
			return notIpAddr
		}
	}
	return apiSucess
}


func (a *hadesApi )processTypeCnamePut(s *apiService, domain string)string {
	if len(s.UpdateMap) != 1{
		return errPutTooManyItems
	}
	for key, val := range s.UpdateMap {
		// check key exist
		name := a.buildDNSNameString(a.domain, key)
		svc := make(map[string]apiService)
		a.doGetHadesRecords(name, svc)
		if len(svc)==0 {
			return noFindAliasName + key
		}
		for _, v := range svc {
			if v.OpsType == "CNAME" && v.AliasDomain != domain{
				return noMatchAliasName +  key
			}
   		 }

		// check val exist
		name = a.buildDNSNameString(a.domain, val)
		_, err := a.etcdClient.Get(hadesmsg.Path(name), true,true)
		if err == nil {
			return errSetAliasNameExists + val
		}

		name = a.buildDNSNameString(a.domain,key)
		ret := a.deleteHadesRecord(name)
		if ret == apiSucess{
			nameNew := a.buildDNSNameString(a.domain,val)
			return a.setHadesRecordHost(nameNew, domain,"CNAME")

		}
		return ret
	}
	return apiSucess
}
func (a *hadesApi)checkKeyEtcdExist( name string )bool{
	_, err  := a.etcdClient.Get(hadesmsg.Path(name),false,true)
	if err == nil{
		return true
	}
	return false
}

func (a *hadesApi)checkPostExist( name string )bool {
	if a.checkK8sSvcDir(name){
		return true
	}
	// check k8s namespaces
	k8sNs := a.buildDNSNameString(a.domain,svcSubdomain,name)
	_, err  := a.etcdClient.Get(hadesmsg.Path(k8sNs),false,true)
	if err == nil{
		return true
	}
	// check user domain set
	userDir := a.buildDNSNameString(a.domain,name)
	_, err  = a.etcdClient.Get(hadesmsg.Path(userDir),false,true)
	if err == nil{
		return true
	}
	return false
}

func (a *hadesApi) statsAuthorization(w http.ResponseWriter, r *http.Request)bool{
	val,ok := r.Header["Token"]
	if !ok{
		fmt.Fprintf(w, "%s\n",noAuthorization)
		return false
	}
	if strings.Compare(val[0], hapi.auth) != 0 {
		fmt.Fprintf(w, "%s\n",errAuthorization)
		return false
	}
	return true
}
func (a *hadesApi)checkK8sSvcDir(domain string)bool{
	return  domain ==svcSubdomain
}
func (a *hadesApi)getReqBody(r *http.Request,s *apiService){
	result, _:= ioutil.ReadAll(r.Body)
	r.Body.Close()

	glog.V(4).Infof("api req body :%s\n" ,result)
	json.Unmarshal([]byte(result), s)
}

func (a *hadesApi)processDelete(w http.ResponseWriter, r *http.Request){

	if ! a.statsAuthorization(w,r){
		return
	}
	vars := mux.Vars(r)
	domain := vars["domain"]
	var s apiService;
	a.getReqBody(r,&s)

	if domain == ""{
		fmt.Fprintf(w, "%s\n",noDomainName)
		return
	}
	if  a.checkK8sSvcDir(domain){
		fmt.Fprintf(w, "%s\n",errDeleteK8sSvc)
		return
	}
	ret := ""
	if s.OpsType == ""{
		name := a.buildDNSNameString(a.domain,domain)
		ret = a.deleteHadesRecord(name)
		fmt.Fprintf(w, "%s\n",ret)
		return
	}
	switch strings.ToUpper(s.OpsType){
	case "A":
		ret = a.processTypeADelete(&s,domain)
	case "CNAME":
		name := a.buildDNSNameString(a.domain,domain)
		ret = a.deleteHadesRecord(name)
	case "NS":
		name := a.buildDNSNameString(a.domain,"ns.dns",domain)
		ret = a.deleteHadesRecord(name)
	case "MX":
		name := a.buildDNSNameString(a.domain,"mail",domain)
		ret = a.deleteHadesRecord(name)
	case "TXT":
		name := a.buildDNSNameString(a.domain,"txt",domain)
		ret = a.deleteHadesRecord(name)
	default:
		ret = noOpsType
	}
	fmt.Fprintf(w, "%s\n",ret)
}
func (a *hadesApi)processPost(w http.ResponseWriter, r *http.Request){
	if ! a.statsAuthorization(w,r){
		return
	}
	vars := mux.Vars(r)
	domain := vars["domain"]
	var s apiService;
	a.getReqBody(r,&s)

	if domain == ""{
		fmt.Fprintf(w, "%s\n",noDomainName)
		return
	}
	if "" == s.OpsType{
		fmt.Fprintf(w, "%s\n",notSupportOpsType)
		return
	}

	ret :=""
	switch strings.ToUpper(s.OpsType){
	case "A":
		// check exitst
		dot := strings.Split(domain,".")
		if len(dot)>1{
			fmt.Fprintf(w, "%s\n",errDomainContainDot)
			return
		}
		if a.checkPostExist(domain){
			fmt.Fprintf(w, "%s\n",errSetDomainNameExists)
			return
		}
		ret = a.processTypeAPost(&s,domain)
	case "CNAME":
		if a.checkPostExist(s.DomainAlias){
			fmt.Fprintf(w, "%s\n",errSetAliasNameExists)
			return
		}
		name := a.buildDNSNameString(a.domain,s.DomainAlias)
		ret = a.setHadesRecordHost(name,domain,"CNAME")
	case "NS":
		name := a.buildDNSNameString(a.domain,"ns.dns",domain)
		if a.checkKeyEtcdExist(name){
			fmt.Fprintf(w, "%s\n",errSetDomainNameExists + domain)
			return
		}
		ret = a.setHadesRecordHost(name,s.NsHost,"NS")
	case "MX":
		name := a.buildDNSNameString(a.domain,"mail",domain)
		if a.checkKeyEtcdExist(name) {
			fmt.Fprintf(w, "%s\n", errSetDomainNameExists + domain)
			return
		}
		ret = a.setHadesRecordMail(name,s.MailHost,s.MailPriority,"MX")

	case "TXT":
		name := a.buildDNSNameString(a.domain,"txt",domain)
		if a.checkKeyEtcdExist(name) {
			fmt.Fprintf(w, "%s\n", errSetDomainNameExists + domain)
			return
		}
		ret = a.setHadesRecordText(name,s.TxtRecord,"TXT")
	default:
		ret= noOpsType
	}
	fmt.Fprintf(w, "%s\n",ret)
	return
}

func (a *hadesApi)processPut(w http.ResponseWriter, r *http.Request){
	if ! a.statsAuthorization(w,r){
		return
	}
	vars := mux.Vars(r)
	domain := vars["domain"]
	var s apiService;
	a.getReqBody(r,&s)

	if domain == ""{
		fmt.Fprintf(w, "%s\n",noDomainName)
		return
	}
	if "" == s.OpsType{
		fmt.Fprintf(w, "%s\n",notSupportOpsType)
		return
	}
	if len(s.UpdateMap) ==0{
		fmt.Fprintf(w, "%s\n",errBodyUpdate)
		return
	}
	ret :=""
	switch strings.ToUpper(s.OpsType){
	case "A":
		ret = a.processTypeAPut(&s,domain)
	case "CNAME":
		ret = a.processTypeCnamePut(&s, domain)
	default:
		ret = noOpsType
	}
	fmt.Fprintf(w, "%s\n",ret)
	return

}
func (a *hadesApi)processGet(w http.ResponseWriter, r *http.Request){
	if ! a.statsAuthorization(w,r){
		return
	}
	vars := mux.Vars(r)
	domain := vars["domain"]
	svc := make(map[string]apiService)
	err := a.getHadesRecords(domain,"A", svc)

	if len(svc) == 0 && err != nil{
		glog.Infof("%s\n", err.Error())
		fmt.Fprintf(w, "%s\n",noFindDomainName)
		return
	}

	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s\n", err.Error())
		fmt.Fprintf(w, "%s\n",errGetDomainName)
		return
	}
	fmt.Fprintf(w, "%s\n",string(b))
	return
}
func (a *hadesApi)processGetAll(w http.ResponseWriter, r *http.Request){
	if ! a.statsAuthorization(w,r){
		return
	}
	var s apiService;
	a.getReqBody(r,&s)
        glog.Infof("s =%s\n",s)

        svc := make(map[string]apiService)
	err := a.getHadesRecords("",s.OpsType, svc)

	if len(svc) == 0 && err != nil{
		glog.Infof("%s\n", err.Error())
		fmt.Fprintf(w, "%s\n",errGetDomainName)
		return
	}

	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s\n", err.Error())
		fmt.Fprintf(w, "%s\n",errGetDomainName)
		return
	}
	fmt.Fprintf(w, "%s\n",string(b))
	return

}

func RunApi(client *tools.EtcdOps, apiAddr string, domain string, auth string, ipMonitorPath string) {

	_, err := net.Dial("tcp", apiAddr)
       if err == nil {
           glog.Fatalf("the addr is used:%s\n",apiAddr)
       }

	glog.Infof("hades api run  with addr =%s domain : %s\n",apiAddr,domain)
	hapi.etcdClient = client
	hapi.domain = domain
	hapi.auth   = auth
	hapi.ipMonitorPath = ipMonitorPath

	r := mux.NewRouter()
	r.HandleFunc("/hades/api", hapi.processGetAll).Methods("GET")
	r.HandleFunc("/hades/api/", hapi.processGetAll).Methods("GET")
	r.HandleFunc("/hades/api/{domain}", hapi.processGet).Methods("GET")
	r.HandleFunc("/hades/api/{domain}", hapi.processDelete).Methods("DELETE")
	r.HandleFunc("/hades/api/{domain}", hapi.processPost).Methods("POST")
	r.HandleFunc("/hades/api/{domain}", hapi.processPut).Methods("PUT")

	go http.ListenAndServe(apiAddr, r)
}
