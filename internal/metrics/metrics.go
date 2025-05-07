package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

type Metrics struct {
	ReconcileCounter              prometheus.Counter
	ReconcileErrorsTotal          *prometheus.CounterVec
	CertificateIssuesTotal        *prometheus.GaugeVec
	CertificateWarningsTotal      *prometheus.GaugeVec
	CertificateErrorsTotal        *prometheus.GaugeVec
	CertificateFoundTotal         *prometheus.GaugeVec
	CertificateIssues             *prometheus.GaugeVec
	PartialCertificatesFoundTotal *prometheus.GaugeVec
	PartialCertificateIssues      *prometheus.GaugeVec
}

func (m *Metrics) NewMetricCleaner() *MetricCleaner {
	return &MetricCleaner{
		metrics: []*prometheus.GaugeVec{
			m.CertificateIssuesTotal,
			m.CertificateFoundTotal,
			m.CertificateIssues,
			m.CertificateWarningsTotal,
			m.CertificateErrorsTotal,
			m.PartialCertificatesFoundTotal,
			m.PartialCertificateIssues,
		},
	}
}

func (m *Metrics) RegisterMetrics() {
	prometheus.MustRegister(m.ReconcileCounter)
	prometheus.MustRegister(m.ReconcileErrorsTotal)
	prometheus.MustRegister(m.CertificateIssuesTotal)
	prometheus.MustRegister(m.CertificateWarningsTotal)
	prometheus.MustRegister(m.CertificateErrorsTotal)
	prometheus.MustRegister(m.CertificateFoundTotal)
	prometheus.MustRegister(m.CertificateIssues)
	prometheus.MustRegister(m.PartialCertificatesFoundTotal)
	prometheus.MustRegister(m.PartialCertificateIssues)
}

type MetricCleaner struct {
	metrics []*prometheus.GaugeVec
	lock    sync.Mutex
}

func NewMetricCleaner(metrics ...*prometheus.GaugeVec) *MetricCleaner {
	return &MetricCleaner{
		metrics: metrics,
	}
}

func New(log *logrus.Entry, reg ctrmetrics.RegistererGatherer, cache k8sclient.Reader) *Metrics {
	//Register the metrics with the provided registerer
	_ = reg.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	_ = reg.Register(collectors.NewGoCollector())

	const MetricNamespace = "paranoia"

	certificateIssuesTotal := promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: MetricNamespace,
		Name:      "certificates_with_issues_total",
		Help:      "Total number of certificates Found with issues",
	}, []string{"container_name", "namespace", "pod_name"})
	certificateWarningsTotal := promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: MetricNamespace,
		Name:      "certificate_warnings_total",
		Help:      "Total number of certificates Found With Warning Status",
	}, []string{"container_name", "namespace", "pod_name"})
	certificateErrorsTotal := promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: MetricNamespace,
		Name:      "certificate_errors_total",
		Help:      "Total number of certificates Found With Error Status",
	}, []string{"container_name", "namespace", "pod_name"})
	certificateFoundTotal := promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: MetricNamespace,
		Name:      "certificate_found_total",
		Help:      "Total number of certificates found",
	}, []string{"container_name", "namespace", "pod_name"})
	certificateIssues := promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: MetricNamespace,
		Name:      "certificate_issues",
		Help:      "Certificates Found with Issues, including Details",
	}, []string{"container_name", "namespace", "pod_name", "certificate", "fingerprint", "reason", "level"})
	partialCertificatesFoundTotal := promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: MetricNamespace,
		Name:      "partial_certificates_found_total",
		Help:      "Total number of partial certificates found",
	}, []string{"container_name", "namespace", "pod_name"})
	partialCertificateIssues := promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: MetricNamespace,
		Name:      "partial_certificate_issues",
		Help:      "Partial certificates found, including details",
	}, []string{"container_name", "namespace", "pod_name", "location", "reason"})
	reconcileCounter := promauto.With(reg).NewCounter(prometheus.CounterOpts{
		Namespace: MetricNamespace,
		Name:      "pod_reconcile_total",
		Help:      "Total number of Pod reconciliations",
	})
	reconcileErrorsTotal := promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
		Namespace: MetricNamespace,
		Name:      "reconcile_errors_total",
		Help:      "Total number of errors encountered during reconciliation",
	}, []string{"namespace", "pod_name", "error_stage"})

	return &Metrics{
		ReconcileCounter:              reconcileCounter,
		ReconcileErrorsTotal:          reconcileErrorsTotal,
		CertificateIssuesTotal:        certificateIssuesTotal,
		CertificateWarningsTotal:      certificateWarningsTotal,
		CertificateErrorsTotal:        certificateErrorsTotal,
		CertificateFoundTotal:         certificateFoundTotal,
		CertificateIssues:             certificateIssues,
		PartialCertificatesFoundTotal: partialCertificatesFoundTotal,
		PartialCertificateIssues:      partialCertificateIssues,
	}
}

func (mc *MetricCleaner) HandlePodDelete(pod *v1.Pod) {
	mc.lock.Lock()
	defer mc.lock.Unlock()

	for _, container := range pod.Spec.Containers {
		labels := prometheus.Labels{
			"pod_name":       pod.Name,
			"namespace":      pod.Namespace,
			"container_name": container.Name, // Use container name from the pod
		}

		logrus.Printf("Deleting metrics for pod: %s, container: %s, namespace: %s", pod.Name, container.Name, pod.Namespace)

		for _, metric := range mc.metrics {
			metric.Delete(labels)
		}
	}
}
