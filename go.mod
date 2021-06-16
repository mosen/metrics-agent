module github.com/cloudability/metrics-agent

go 1.14

require (
	github.com/evanphx/json-patch v4.9.0+incompatible // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/golangci/golangci-lint v1.23.8
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/googleapis/gnostic v0.4.0 // indirect
	github.com/gostaticanalysis/analysisutil v0.0.3 // indirect
	github.com/json-iterator/go v1.1.10 // indirect
	github.com/kr/pretty v0.2.0 // indirect
	github.com/onsi/gomega v1.10.2
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/viper v1.6.2
	golang.org/x/crypto v0.0.0-20200220183623-bac4c82f6975 // indirect
	golang.org/x/oauth2 v0.0.0-20191202225959-858c2ad4c8b6 // indirect
	golang.org/x/sys v0.0.0-20200622214017-ed371f2e16b4 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	golang.org/x/tools v0.0.0-20200616133436-c1934b75d054 // indirect
	google.golang.org/appengine v1.6.5 // indirect
	google.golang.org/protobuf v1.24.0 // indirect
	k8s.io/api v0.17.3
	k8s.io/apimachinery v0.17.3
	k8s.io/client-go v0.17.3
	k8s.io/kube-openapi v0.0.0-20200121204235-bf4fb3bd569c // indirect
	k8s.io/utils v0.0.0-20200729134348-d5654de09c73 // indirect
	sigs.k8s.io/kind v0.7.0
	sigs.k8s.io/yaml v1.2.0 // indirect
)

replace (
	k8s.io/api v0.0.0 => k8s.io/api v0.17.3
	k8s.io/apiextensions-apiserver v0.0.0 => k8s.io/apiextensions-apiserver v0.17.3
	k8s.io/apimachinery v0.0.0 => k8s.io/apimachinery v0.17.3
	k8s.io/apiserver v0.0.0 => k8s.io/apiserver v0.17.3
	k8s.io/cli-runtime v0.0.0 => k8s.io/cli-runtime v0.17.3
	k8s.io/client-go v0.0.0 => k8s.io/client-go v0.17.3
	k8s.io/cloud-provider v0.0.0 => k8s.io/cloud-provider v0.17.3
	k8s.io/cluster-bootstrap v0.0.0 => k8s.io/cluster-bootstrap v0.17.3
	k8s.io/code-generator v0.0.0 => k8s.io/code-generator v0.17.3
	k8s.io/component-base v0.0.0 => k8s.io/component-base v0.17.3
	k8s.io/cri-api v0.0.0 => k8s.io/cri-api v0.17.3
	k8s.io/csi-translation-lib v0.0.0 => k8s.io/csi-translation-lib v0.17.3
	k8s.io/kube-aggregator v0.0.0 => k8s.io/kube-aggregator v0.17.3
	k8s.io/kube-controller-manager v0.0.0 => k8s.io/kube-controller-manager v0.17.3
	k8s.io/kube-proxy v0.0.0 => k8s.io/kube-proxy v0.17.3
	k8s.io/kube-scheduler v0.0.0 => k8s.io/kube-scheduler v0.17.3
	k8s.io/kubectl v0.0.0 => k8s.io/kubectl v0.17.3
	k8s.io/kubelet v0.0.0 => k8s.io/kubelet v0.17.3
	k8s.io/legacy-cloud-providers v0.0.0 => k8s.io/legacy-cloud-providers v0.17.3
	k8s.io/metrics v0.0.0 => k8s.io/metrics v0.17.3
	k8s.io/sample-apiserver v0.0.0 => k8s.io/sample-apiserver v0.17.3
)
