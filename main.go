package main

import (
	"context"
	"flag"
	"os/exec"
	"strconv"

	log "github.com/sirupsen/logrus"

	"strings"

	"io/ioutil"
	"net"

	"sync"

	"github.com/fsnotify/fsnotify"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	user_list  = make(map[string][]access)
	user       = make(map[string]string)
	kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file. If not defined ServiceAccount will be used")
	ccd        = flag.String("ccd", "/etc/openvpn/ccd", "path to directory with ccd files. If not defined /etc/openvpn/ccd will be used")
	clientset  *kubernetes.Clientset
	mutex      = sync.RWMutex{}
)

type access struct {
	namespace string
	label     string
	network   string
	netmask   string
}

func fRead(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		log.Println(err)
		return ""
	}

	return string(content)
}

func load_ccd(file string, init ...bool) {
	var txtLinesArray []string
	var desc string
	var namespace string
	var label string
	var ip = ""

	ccd_name := strings.TrimPrefix(file, *ccd+"/")

	log.Println("parse ccd:", file)
	txtLinesArray = strings.Split(fRead(file), "\n")
	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) > 0 {
			switch {
			case strings.HasPrefix(str[0], "ifconfig-push"):
				ip = str[1]
				mutex.Lock()
				user[ccd_name] = ip
				log.Infof("User %s use static IP %s", ccd_name, ip)
				user_list[ccd_name] = nil
				mutex.Unlock()

			case strings.HasPrefix(str[0], "push"):
				log.Debug("route:", strings.Trim(str[2], "\""))
				log.Debug("mask:", strings.Trim(str[3], "\""))
				desc = strings.Trim(strings.Join(str[4:], ""), "#")
				log.Debug("desc:", desc)
				namespace = ""
				label = ""
				if strings.Contains(desc, ":") {
					s := strings.Split(desc, ":")
					namespace = s[0]
					label = s[1]
				}
				if ip != "" {
					mutex.Lock()
					user_list[ccd_name] = append(user_list[ccd_name], access{namespace: namespace, label: label, network: strings.Trim(str[2], "\""), netmask: strings.Trim(str[3], "\"")})
					mutex.Unlock()
				}
			}
		}
	}
	if ip != "" {
		exec.Command("sh", "-c", "ipset -N "+ccd_name+" nethash").Run()
		exec.Command("sh", "-c", "iptables -D FORWARD -s "+ip+" -m set ! --match-set "+ccd_name+" dst -j REJECT").Run()
		exec.Command("sh", "-c", "iptables -D FORWARD -s "+ip+" -m set ! --match-set "+ccd_name+" dst -j REJECT").Run()
		if err := exec.Command("ipset", "-F", ccd_name).Run(); err == nil {
			log.Infof("flush firewall rules for %s (%s)", ccd_name, ip)
		}
		mutex.RLock()
		for _, val := range user_list[ccd_name] {
			if val.namespace == "" {
				mask, _ := net.IPMask(net.ParseIP(val.netmask).To4()).Size()
				if err := exec.Command("ipset", "-A", ccd_name, val.network+"/"+strconv.Itoa(mask)).Run(); err == nil {
					log.Infof("grant access for %s (%s) to network %s/%s", ccd_name, ip, val.network, strconv.Itoa(mask))
				}
			}
		}
		mutex.RUnlock()
		if len(init) == 0 {
			pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				log.Fatal(err)
			}
			for _, p := range pods.Items {
				addPod(&p)
			}
			services, err := clientset.CoreV1().Services("").List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				log.Fatal(err)
			}
			for _, s := range services.Items {
				addService(&s)
			}
		}
		if err := exec.Command("sh", "-c", "iptables -I FORWARD -s "+ip+" -m set ! --match-set "+ccd_name+" dst -j REJECT").Run(); err == nil {
			log.Infof("enable firewall rules for %s (%s)", ccd_name, ip)
		}
	}
}
func updatePod(oldobj interface{}, obj interface{}) {
        addPod(obj)
}
func addPod(obj interface{}) {
	pod := obj.(*v1.Pod)
	if pod.Status.PodIP != "" {
		mutex.RLock()
		for ccd_name, routes := range user_list {
			for _, val := range routes {
				if val.namespace == pod.ObjectMeta.Namespace || val.namespace == "*" {
					if val.label == "*" {
						if err := exec.Command("ipset", "-A", ccd_name, pod.Status.PodIP).Run(); err == nil {
							log.Infof("grant access for %s (%s) to pod %s with ip %s in namespace %s using template %s:%s", ccd_name, user[ccd_name], pod.Name, pod.Status.PodIP, pod.ObjectMeta.Namespace, val.namespace, val.label)
						}
					} else {
						for podLabel, podLabelValue := range pod.ObjectMeta.Labels {
							lv := podLabel + "=" + podLabelValue
							if lv == val.label {
								if err := exec.Command("ipset", "-A", ccd_name, pod.Status.PodIP).Run(); err == nil {
									log.Infof("grant access for %s (%s) to pod %s with ip %s in namespace %s using template %s:%s", ccd_name, user[ccd_name], pod.Name, pod.Status.PodIP, pod.ObjectMeta.Namespace, val.namespace, val.label)
								}
								break
							}
						}
					}
				}
			}
		}
		mutex.RUnlock()
	}
}
func delPod(obj interface{}) {
	pod := obj.(*v1.Pod)
	if pod.Status.PodIP != "" {
		mutex.RLock()
		for ccd_name := range user_list {
			if err := exec.Command("ipset", "-D", ccd_name, pod.Status.PodIP).Run(); err == nil {
				log.Infof("deleted access for %s (%s) to pod %s with ip %s in namespace %s", ccd_name, user[ccd_name], pod.Name, pod.Status.PodIP, pod.ObjectMeta.Namespace)
			}
		}
		mutex.RUnlock()
	}
}

func addService(obj interface{}) {
	svc := obj.(*v1.Service)
	if svc.Spec.ClusterIP != "None" {
		//log.Infof("service %s namespace %s clusteip %s", svc.ObjectMeta.Name, svc.ObjectMeta.Namespace, svc.Spec.ClusterIP)
		mutex.RLock()
		for ccd_name, routes := range user_list {
			for _, val := range routes {
				if val.namespace == svc.ObjectMeta.Namespace || val.namespace == "*" {
					if val.label == "*" {
						if err := exec.Command("ipset", "-A", ccd_name, svc.Spec.ClusterIP).Run(); err == nil {
							log.Infof("grant access for %s (%s) to service %s with ip %s in namespace %s using template %s:%s", ccd_name, user[ccd_name], svc.Name, svc.Spec.ClusterIP, svc.ObjectMeta.Namespace, val.namespace, val.label)
						}
					} else {
						for svcLabel, svcLabelValue := range svc.ObjectMeta.Labels {
							lv := svcLabel + "=" + svcLabelValue
							if lv == val.label {
								if err := exec.Command("ipset", "-A", ccd_name, svc.Spec.ClusterIP).Run(); err == nil {
									log.Infof("grant access for %s (%s) to service %s with ip %s in namespace %s using template %s:%s", ccd_name, user[ccd_name], svc.Name, svc.Spec.ClusterIP, svc.ObjectMeta.Namespace, val.namespace, val.label)
								}
								break
							}
						}
					}
				}
			}
		}
		mutex.RUnlock()
	}
}
func delService(obj interface{}) {
	svc := obj.(*v1.Service)
	if svc.Spec.ClusterIP != "None" {
		mutex.RLock()
		//log.Infof("service %s namespace %s clusteip %s", svc.ObjectMeta.Name, svc.ObjectMeta.Namespace, svc.Spec.ClusterIP)
		for ccd_name := range user_list {
			if err := exec.Command("ipset", "-D", ccd_name, svc.Spec.ClusterIP).Run(); err == nil {
				log.Infof("deleted access for %s (%s) to service %s with ip %s in namespace %s", ccd_name, user[ccd_name], svc.Name, svc.Spec.ClusterIP, svc.ObjectMeta.Namespace)
			}
		}
		mutex.RUnlock()
	}
}

func main() {

	flag.Parse()

	ccdDir := *ccd

	if err := exec.Command("ipset", "-S").Run(); err != nil {
		log.Fatal("Error execute ipset ", err)
	}
	if err := exec.Command("iptables", "-nL").Run(); err != nil {
		log.Fatal("Error execute iptables ", err)
	}

	// Create new watcher.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	var kconfig *rest.Config

	if len(*kubeconfig) > 0 {
		kconfig, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
	} else {
		kconfig, err = rest.InClusterConfig()
	}

	if err != nil {
		log.Fatal(err)
	}

	clientset, err = kubernetes.NewForConfig(kconfig)
	if err != nil {
		log.Fatal(err)
	}

	files, err := ioutil.ReadDir(ccdDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		log.Println("found file: " + ccdDir + "/" + file.Name())
		load_ccd(ccdDir+"/"+file.Name(), true)
	}

	// Start listening for events.
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) {
					log.Println("modified file:", event.Name)
					load_ccd(event.Name)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	// Add a path.
	err = watcher.Add(ccdDir)
	if err != nil {
		log.Fatal(err)
	}

	_, podController := cache.NewInformer(
		cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(),
			string(v1.ResourcePods), v1.NamespaceAll, fields.Everything()),
		&v1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    addPod,
			UpdateFunc: updatePod,
			DeleteFunc: delPod,
		},
	)
	podStop := make(chan struct{})
	defer close(podStop)
	go podController.Run(podStop)

	_, svcController := cache.NewInformer(
		cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(),
			string(v1.ResourceServices), v1.NamespaceAll, fields.Everything()),
		&v1.Service{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    addService,
			DeleteFunc: delService,
		},
	)
	svcStop := make(chan struct{})
	defer close(svcStop)
	go svcController.Run(svcStop)

	// Block main goroutine forever.
	<-make(chan struct{})
}
