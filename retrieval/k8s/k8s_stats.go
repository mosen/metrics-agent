package k8s

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/cloudability/metrics-agent/retrieval/raw"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

// ListResponse is a base object for unmarshaling k8s objects from the JSON files containing them. It captures
// the general fields present on all the responses.
type ListResponse struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   map[string]string `json:"metadata"`
	Code       int               `json:"code"`
	Details    map[string]string `json:"details"`
	Message    string            `json:"message"`
	Reason     string            `json:"reason"`
	Status     string            `json:"status"`
}

type PodList struct {
	ListResponse
	Items []corev1.Pod `json:"items"`
}

func GetCAdvisorPods(clusterHostURL string, rawClient raw.Client) (hasCadvisor bool, podIPs []string, rerr error) {
	// TODO: check for cAdvisor daemonset
	_, statusCode, err := rawClient.Get(http.MethodGet, "namespaces", clusterHostURL+"/api/v1/namespaces/cadvisor", nil)
	if statusCode == 404 {
		return false, podIPs, err
	}
	if err != nil {
		return hasCadvisor, podIPs, err
	}
	hasCadvisor = true
	body, statusCode, err := rawClient.Get(http.MethodGet, "pods", clusterHostURL+"/api/v1/namespaces/cadvisor/pods/", nil)
	if err != nil {
		return hasCadvisor, podIPs, err
	}
	if !(statusCode >= 200 && statusCode <= 299) {
		return hasCadvisor, podIPs, fmt.Errorf("Invalid response %s", strconv.Itoa(statusCode))
	}
	podList := PodList{}
	err = json.Unmarshal(body, &podList)
	if err != nil {
		return hasCadvisor, podIPs, fmt.Errorf("error unmarshaling: %v", err)
	}
	log.Info("Num pods:", len(podList.Items))
	podIPs = make([]string, 0, len(podList.Items))
	for _, pod := range podList.Items {
		log.Info("POD IP:", pod.Status.PodIP)
		podIPs = append(podIPs, pod.Status.PodIP)
	}
	return true, podIPs, nil
}

//GetK8sMetrics returns cloudabilty measurements retrieved from a given K8S Clientset
func GetK8sMetrics(clusterHostURL string, clusterVersion float64, workDir *os.File, rawClient raw.Client) (err error) {

	v1Sources, v1beta1Sources, v1AppSources := getk8sSourcePaths(clusterVersion)

	// get v1 sources
	for _, v1s := range v1Sources {
		_, err := rawClient.GetRawEndPoint(http.MethodGet, v1s, workDir, clusterHostURL+"/api/v1/"+v1s, nil, true)
		if err != nil {
			log.Errorf("Error retrieving "+v1s+" metric endpoint: %s", err)
			return err
		}
	}

	// get v1beta1 sources
	for _, v1b1s := range v1beta1Sources {
		_, err := rawClient.GetRawEndPoint(
			http.MethodGet, v1b1s, workDir, clusterHostURL+"/apis/extensions/v1beta1/"+v1b1s, nil, true)
		if err != nil {
			log.Errorf("Error retrieving "+v1b1s+" metric endpoint: %s", err)
			return err
		}
	}

	// get v1 App sources
	for _, v1Apps := range v1AppSources {
		_, err := rawClient.GetRawEndPoint(http.MethodGet, v1Apps, workDir, clusterHostURL+"/apis/apps/v1/"+v1Apps, nil, true)
		if err != nil {
			log.Errorf("Error retrieving "+v1Apps+" metric endpoint: %s", err)
			return err
		}
	}

	// get jobs
	_, err = rawClient.GetRawEndPoint(http.MethodGet, "jobs", workDir, clusterHostURL+"/apis/batch/v1/jobs", nil, true)
	if err != nil {
		log.Errorf("Error retrieving jobs metric endpoint: %s", err)
		return err
	}

	return err
}

func getk8sSourcePaths(clusterVersion float64) (v1Sources []string, v1beta1Sources []string, v1AppSources []string) {
	commonSrcs := []string{
		"replicasets",
		"daemonsets",
		"deployments",
	}
	v1Sources = []string{
		"namespaces",
		"replicationcontrollers",
		"services",
		"nodes",
		"pods",
		"persistentvolumes",
		"persistentvolumeclaims",
	}

	v1beta1Sources = []string{}
	v1AppSources = []string{}

	// common sources [deployments, replicasets, daemonsets] moved from beta to apps v1.16 onward
	if clusterVersion < 1.16 {
		v1beta1Sources = append(v1beta1Sources, commonSrcs...)
	} else {
		v1AppSources = append(v1AppSources, commonSrcs...)
	}

	return v1Sources, v1beta1Sources, v1AppSources

}
