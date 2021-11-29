package ars

import (
	"github.com/goharbor/harbor/src/common/utils/log"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var k8sClientSet kubernetes.Interface

func init() {

	log.Debug("initialize kubernetes client...")

	config, err := LoadKubeConfig()
	if err != nil {
		panic(err)
	}
	k8sClientSet, err = kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}
}

// LoadKubeConfig loads config for accessing k8s API server.
func LoadKubeConfig() (*rest.Config, error) {

	log.Debugf("running in cluster")
	config, err := rest.InClusterConfig()
	return config, err
}
