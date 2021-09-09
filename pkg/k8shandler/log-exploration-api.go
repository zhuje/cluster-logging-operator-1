package k8shandler

import (
	"github.com/ViaQ/logerr/log"
	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	route "github.com/openshift/api/route/v1"
	"github.com/openshift/cluster-logging-operator/pkg/factory"
	"github.com/openshift/cluster-logging-operator/pkg/utils"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	logAPIPort = 8080
	logAPIName = "logexplorationapi"
	logAPIMetricsPortName = "prom-metrics"
)

func (clusterRequest *ClusterLoggingRequest)  createLogExplorationAPIServiceMonitor() error {
	log.Info("hello from createLogExplorationAPIServiceMonitor()10")

	cluster := clusterRequest.Cluster

	desired := NewServiceMonitor("logexplorationapi-service-monitor", cluster.Namespace)

	endpoint := monitoringv1.Endpoint{
		Port:   logAPIMetricsPortName,
		Path:   "/metrics",
		Scheme: "http",
		//Scheme: "https",
		//TLSConfig: &monitoringv1.TLSConfig{
		//	CAFile:     prometheusCAFile,
		//	ServerName: fmt.Sprintf("%s.%s.svc", logAPIName, cluster.Namespace),
		//	//ServerName can be e.g. logexplorationapi.openshift-logging.svc
		//},
	}

	// JZ: metrics exporter is not included becuase those are use to funnel
	// data from third party systems as Promthesus metrics

	// JZ : match the label given to deployment
	labelSelector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"app": logAPIName,
		},
	}

	// JZ : pulling all the pieces together to make one servicemonitor object
	desired.Spec = monitoringv1.ServiceMonitorSpec{
		JobLabel:  "monitor-logexplorationapi",
		Endpoints: []monitoringv1.Endpoint{endpoint},
		Selector:  labelSelector,
		NamespaceSelector: monitoringv1.NamespaceSelector{
			MatchNames: []string{cluster.Namespace},
		},
	}

	utils.AddOwnerRefToObject(desired, utils.AsOwner(cluster))

	err := clusterRequest.Create(desired)
	if err != nil {
		return err

	//if err != nil {
	//	if !errors.IsAlreadyExists(err) {
	//		return fmt.Errorf("Failure creating the log-exploration-api ServiceMonitor : %v", err)
	//	}
	//	current := &monitoringv1.ServiceMonitor{}
	//	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
	//		if err = clusterRequest.Get(desired.Name, current); err != nil {
	//			if errors.IsNotFound(err) {
	//				// the object doesn't exist -- it was likely culled
	//				// recreate it on the next time through if necessary
	//				return nil
	//			}
	//			return fmt.Errorf("Failed to get %q service for %q: %v", current.Name, clusterRequest.Cluster.Name, err)
	//		}
	//		if servicemonitor.AreSame(current, desired) {
	//			log.V(3).Info("ServiceMonitor are the same skipping update")
	//			return nil
	//		}
	//		current.Labels = desired.Labels
	//		current.Spec = desired.Spec
	//		current.Annotations = desired.Annotations
	//
	//		return clusterRequest.Update(current)
	//	})
	//	log.V(3).Error(retryErr, "Reconcile ServiceMonitor retry error")
	//	return retryErr
	}
	return nil
}


func newLogExplorationAPIRoute(routeName, namespace, serviceName, componentName, loggingComponent string) *route.Route {
	return &route.Route{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Route",
			APIVersion: route.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      routeName,
			Namespace: namespace,
			Labels: map[string]string{
				"component":     componentName,
				"logging-infra": loggingComponent,
			},
		},
		Spec: route.RouteSpec{
			To: route.RouteTargetReference{
				Name: serviceName,
				Kind: "Service",
			},
		},
	}
}

func (clusterRequest *ClusterLoggingRequest) createLogExplorationAPIService() error {
	desired := factory.NewService(
		"logexplorationapi-service",
		clusterRequest.Cluster.Namespace,
		"logexplorationapi",
		[]v1.ServicePort{
			{
				Port:       logAPIPort,
				TargetPort: intstr.FromInt(logAPIPort),
				Name: logAPIMetricsPortName,
			},
		},
	)

	// JZ: Override the Label from factory.NewService
	desired.Labels = map[string]string{
		"app" : logAPIName,
	}

	utils.AddOwnerRefToObject(desired, utils.AsOwner(clusterRequest.Cluster))
	err := clusterRequest.Create(desired)
	return err
}
func (clusterRequest *ClusterLoggingRequest) createLogExplorationAPIRoute() error {
	apiRoute := newLogExplorationAPIRoute("logexplorationapi-route", clusterRequest.Cluster.Namespace, "logexplorationapi-service", "logexplorationapi", "logexplorationapi")
	utils.AddOwnerRefToObject(apiRoute, utils.AsOwner(clusterRequest.Cluster))
	err := clusterRequest.Create(apiRoute)
	return err
}
func (clusterRequest *ClusterLoggingRequest) createLogExplorationAPIDeployment() error {

	logApiPodSpec := newLogExplorationApiPodSpec()

	logApiDeployment := NewDeployment("logexplorationapi", clusterRequest.Cluster.Namespace, "logexplorationapi", "logexplorationapi", logApiPodSpec)

	utils.AddOwnerRefToObject(logApiDeployment, utils.AsOwner(clusterRequest.Cluster))

	err := clusterRequest.Create(logApiDeployment)
	if err != nil {
		return err
	}

	return nil

}

func newLogExplorationApiPodSpec() v1.PodSpec {
	resources := &v1.ResourceRequirements{
		Limits: v1.ResourceList{
			v1.ResourceMemory: defaultLoggingApiMemory,
			v1.ResourceCPU:    defaultLoggingApiCpuRequest,
		},
		Requests: v1.ResourceList{
			v1.ResourceMemory: defaultLoggingApiMemory,
			v1.ResourceCPU:    defaultLoggingApiCpuRequest,
		},
	}

	logExplorationApiContainer := NewContainer("logexplorationapi", "logApi", v1.PullIfNotPresent, *resources)

	logExplorationApiContainer.Ports = []v1.ContainerPort{
		{
			ContainerPort: logAPIPort,
		},
	}
	logExplorationApiContainer.Env = []v1.EnvVar{
		{Name: "ES_ADDR", Value: "https://elasticsearch.openshift-logging:9200"},
		{Name: "ES_CERT", Value: "/etc/openshift/elasticsearch/secret/tls.crt"},
		{Name: "ES_KEY", Value: "/etc/openshift/elasticsearch/secret/tls.key"},
		{Name: "ES_TLS", Value: "true"},
		{Name: "POD_IP", ValueFrom: &v1.EnvVarSource{FieldRef: &v1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "status.podIP"}}},
	}

	logExplorationApiContainer.VolumeMounts = []v1.VolumeMount{
		{Name: "certificates", MountPath: "/etc/openshift/elasticsearch/secret"},
	}
	httpGetStructLivenessProbe := &v1.HTTPGetAction{
		Path: "/ready",
		Port: intstr.FromInt(logAPIPort),
	}
	httpGetStructReadinessProbe := &v1.HTTPGetAction{
		Path: "/health",
		Port: intstr.FromInt(logAPIPort),
	}
	handlerStructLivenessProbe := v1.Handler{
		HTTPGet: httpGetStructLivenessProbe,
	}

	handlerStructReadinessProbe := v1.Handler{
		HTTPGet: httpGetStructReadinessProbe,
	}
	logExplorationApiContainer.ReadinessProbe = &v1.Probe{
		Handler:             handlerStructReadinessProbe,
		InitialDelaySeconds: 3,
		PeriodSeconds:       3,
	}
	logExplorationApiContainer.LivenessProbe = &v1.Probe{
		Handler:             handlerStructLivenessProbe,
		InitialDelaySeconds: 10,
		PeriodSeconds:       3,
		FailureThreshold:    30,
	}

	logExplorationApiPodSpec := newLogApiPodSpec([]v1.Container{logExplorationApiContainer},
		[]v1.Volume{
			{Name: "certificates", VolumeSource: v1.VolumeSource{Secret: &v1.SecretVolumeSource{SecretName: "fluentd", DefaultMode: utils.GetInt32(420)}}},
		},
	)
	return logExplorationApiPodSpec

}

func newLogApiPodSpec(containers []v1.Container, volumes []v1.Volume) v1.PodSpec {

	return v1.PodSpec{
		Containers: containers,
		Volumes:    volumes,
	}
}

// JZ: remove the print statements
func (clusterRequest *ClusterLoggingRequest) CreateOrDeleteLogExplorationApi() error {
	log.Info("CreateOrDeleteLogExplorationAPI entered")
	if _, ok := clusterRequest.Cluster.Annotations["api-enabled"]; ok {
		log.Info("api-enabled is TRUE")

		if err := clusterRequest.createLogExplorationAPIDeployment(); err != nil {
			log.Info("ERROR: CreateOrDeleteLogExplorationAPI > Deployment")
			//return err
		}
		if err := clusterRequest.createLogExplorationAPIService(); err != nil {
			log.Info("ERROR: CreateOrDeleteLogExplorationAPI > Service")

			//return err
		}
		if err := clusterRequest.createLogExplorationAPIRoute(); err != nil {
			log.Info("ERROR: CreateOrDeleteLogExplorationAPI > Route")

			//return err
		}
		if err := clusterRequest.createLogExplorationAPIServiceMonitor(); err != nil {
			log.Info("ERROR: CreateOrDeleteLogExplorationAPI > ServiceMonitor")

			//return err
		}

	} else {
		log.Info("api-enabled is FALSE")

		if err := clusterRequest.RemoveDeployment("logging-api"); err != nil {
			log.Info("ERROR: CreateOrDeleteLogExplorationAPI > RemoveDeployment")

			return err
		}
		if err := clusterRequest.RemoveService("logexplorationapi-service"); err != nil {
			log.Info("ERROR: CreateOrDeleteLogExplorationAPI > RemoveService")

			return err
		}
		if err := clusterRequest.RemoveRoute("logexplorationapi-route"); err != nil {
			log.Info("ERROR: CreateOrDeleteLogExplorationAPI > RemoveRoute")

			return err
		}

		if err := clusterRequest.RemoveServiceMonitor("logexplorationapi-service-monitor"); err != nil {
			log.Info("ERROR: CreateOrDeleteLogExplorationAPI > RemoveServiceMonitor")
			return err
		}

	}
	return nil
}
