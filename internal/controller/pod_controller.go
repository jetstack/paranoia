package controller

import (
	"context"
	"encoding/hex"
	"fmt"
	"path"
	"time"

	"github.com/jetstack/paranoia/cmd/options"
	"github.com/jetstack/paranoia/internal/analyse"
	"github.com/jetstack/paranoia/internal/image"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	reconcileCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "pod_reconcile_total",
			Help: "Total number of Pod reconciliations",
		},
	)
	certificateIssuesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "certificates_with_issues_total",
			Help: "Total number of certificates Found with issues",
		},
		[]string{"container_name", "namespace"},
	)
	certificateWarningsTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "certificate_warnings_total",
			Help: "Total number of certificates Found With Warning Status",
		},
		[]string{"container_name", "namespace"},
	)
	certificateErrorsTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "certificate_errors_total",
			Help: "Total number of certificates Found With Error Status",
		},
		[]string{"container_name", "namespace"},
	)
	certificateFoundTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "certificate_found_total",
			Help: "Total number of certificates found",
		},
		[]string{"container_name", "namespace"},
	)
	certificateIssues = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "certificate_issues",
			Help: "Certificates Found with Issues, including Details",
		},
		[]string{"container_name", "namespace", "certificate", "fingerprint", "reason", "level"},
	)
	partialCertificatesFoundTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "partial_certificates_found_total",
			Help: "Total number of partial certificates found",
		},
		[]string{"container_name", "namespace"},
	)
	partialCertificateIssues = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "partial_certificate_issues",
			Help: "Partial certificates found, including details",
		},
		[]string{"container_name", "namespace", "location", "reason"},
	)
)

func init() {
	// Register metrics with Prometheus
	prometheus.MustRegister(reconcileCounter)
	prometheus.MustRegister(certificateIssuesTotal)
	prometheus.MustRegister(certificateFoundTotal)
	prometheus.MustRegister(certificateIssues)
	prometheus.MustRegister(certificateWarningsTotal)
	prometheus.MustRegister(certificateErrorsTotal)
	prometheus.MustRegister(partialCertificatesFoundTotal)
	prometheus.MustRegister(partialCertificateIssues)
}

// PodReconciler reconciles a Pod object
type PodReconciler struct {
	k8sclient.Client
	Scheme *runtime.Scheme
	Log    *logrus.Entry
}

func NewPodReconciler(
	kubeClient k8sclient.Client,
	log *logrus.Entry,
) *PodReconciler {
	return &PodReconciler{
		Client: kubeClient,
		Log:    log,
	}
}

// Reconcile is part of the main kubernetes reconciliation loop
func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Increment reconciliation counter
	reconcileCounter.Inc()

	// Fetch the Pod instance
	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Pod resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get Pod.")
		return ctrl.Result{}, err
	}

	// Example logic: Log the pod name and namespace
	logger.Info(fmt.Sprintf("Reconciling Pod: %s/%s", pod.Namespace, pod.Name))

	// Add your reconciliation logic here
	for _, container := range pod.Spec.Containers {
		if match, _ := path.Match("sleep-*", pod.Name); match {
			logger.Info("Found sleep-pod container, inspecting image")
			imageName := container.Image

			imgOpts := &options.Image{} // Initialize imgOpts
			iOpts, err := imgOpts.Options()
			if err != nil {
				return ctrl.Result{}, errors.Wrap(err, "constructing image options")
			}

			parsedCertificates, err := image.FindImageCertificates(ctx, imageName, iOpts...)
			if err != nil {
				return ctrl.Result{}, err
			}

			analyser, err := analyse.NewAnalyser()
			if err != nil {
				return ctrl.Result{}, errors.Wrap(err, "failed to initialise analyser")
			}

			numIssues := 0
			numError := 0
			numWarn := 0

			for _, cert := range parsedCertificates.Found {
				if cert.Certificate == nil {
					numIssues++
					continue
				}
				notes := analyser.AnalyseCertificate(cert.Certificate)

				if len(notes) > 0 {
					numIssues++
					fingerprint := hex.EncodeToString(cert.FingerprintSha256[:])
					// Need to workout what to do with the numIssues here
					for _, n := range notes {
						if n.Level == analyse.NoteLevelError {
							numError++
							certificateIssues.WithLabelValues(container.Name, pod.Namespace, cert.Certificate.Subject.String(), fingerprint, n.Reason, "error").Set(float64(1))
						} else if n.Level == analyse.NoteLevelWarn {
							numWarn++
							certificateIssues.WithLabelValues(container.Name, pod.Namespace, cert.Certificate.Subject.String(), fingerprint, n.Reason, "warn").Set(float64(1))
						}
					}
					logger.Info(fmt.Sprintf("Certificate %s, Fingerprint: %s", cert.Certificate.Subject, fingerprint))
				}
			}
			certificateIssuesTotal.WithLabelValues(container.Name, pod.Namespace).Set(float64(numIssues))
			certificateWarningsTotal.WithLabelValues(container.Name, pod.Namespace).Set(float64(numWarn))
			certificateErrorsTotal.WithLabelValues(container.Name, pod.Namespace).Set(float64(numError))
			certificateFoundTotal.WithLabelValues(container.Name, pod.Namespace).Set(float64(len(parsedCertificates.Found)))
			partialCertificatesFoundTotal.WithLabelValues(container.Name, pod.Namespace).Set(float64(len(parsedCertificates.Partials)))
			logger.Info(fmt.Sprintf("Found %d certificates total, of which %d had issues", len(parsedCertificates.Found), numIssues))

			if len(parsedCertificates.Partials) > 0 {
				for _, p := range parsedCertificates.Partials {
					partialCertificateIssues.WithLabelValues(container.Name, pod.Namespace, p.Location, p.Reason).Set(float64(1))
					logger.Info(fmt.Sprintf("Partial certificate found in file %s: %s", p.Location, p.Reason))
				}
			}
		}
	}

	// Ensure the controller is requeued to run again after 2 minutes
	return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}
