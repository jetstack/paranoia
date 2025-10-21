package controller

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"slices"

	"github.com/jetstack/paranoia/cmd/options"
	"github.com/jetstack/paranoia/internal/analyse"
	"github.com/jetstack/paranoia/internal/image"
	"github.com/jetstack/paranoia/internal/metrics"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// PodReconciler reconciles a Pod object
type PodReconciler struct {
	k8sclient.Client
	Metrics            *metrics.Metrics
	Scheme             *runtime.Scheme
	Log                *logrus.Entry
	cleaner            *metrics.MetricCleaner
	semaphore          chan struct{} // Semaphore to limit concurrency
	ExcludedNamespaces []string
	RequeueTime        time.Duration
}

func NewPodReconciler(
	kubeClient k8sclient.Client,
	log *logrus.Entry,
	metrics *metrics.Metrics,
	maxConcurrentReconciles int,
	excludedNamespaces []string,
	RequeueTime time.Duration,
) *PodReconciler {
	log = log.WithField("controller", "pod")
	r := &PodReconciler{
		Log:                log,
		Client:             kubeClient,
		Metrics:            metrics,
		semaphore:          make(chan struct{}, maxConcurrentReconciles), // Initialize semaphore
		ExcludedNamespaces: excludedNamespaces,
		RequeueTime:        RequeueTime,
	}

	// Register metrics with Prometheus
	metrics.RegisterMetrics()
	r.cleaner = metrics.NewMetricCleaner()

	return r
}

func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Acquire semaphore
	r.semaphore <- struct{}{}
	defer func() { <-r.semaphore }() // Release semaphore when done

	logger := log.FromContext(ctx)

	// Initialize reconcile_errors_total metric to 0
	r.Metrics.ReconcileErrorsTotal.WithLabelValues(req.Namespace, req.Name, "get_pod").Add(0)

	// Check if namespace is excluded
	if slices.Contains(r.ExcludedNamespaces, req.Namespace) {
		logger.Info("Skipping reconciliation for excluded namespace", "namespace", req.Namespace)
		return ctrl.Result{}, nil
	}

	// Increment reconciliation counter
	r.Metrics.ReconcileCounter.Inc()

	// Fetch the Pod instance
	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Pod resource not found. Cleaning up metrics.")
			r.cleaner.HandlePodDelete(&pod) // Ensure pod contains correct labels
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get Pod.")
		r.Metrics.ReconcileErrorsTotal.WithLabelValues(req.Namespace, req.Name, "get_pod").Inc() // Increment error metric
		return ctrl.Result{}, err
	}

	// Skip reconciliation if the pod is being deleted
	if !pod.DeletionTimestamp.IsZero() {
		logger.Info("Pod resource is being deleted. Cleaning up metrics.")
		r.cleaner.HandlePodDelete(&pod) // Ensure pod contains correct labels
		return ctrl.Result{}, nil
	}

	logger.Info(fmt.Sprintf("Reconciling Pod: %s/%s", pod.Namespace, pod.Name))

	for _, container := range pod.Spec.Containers {
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

		analyser, err := analyse.NewAnalyser(&options.Analyse{})
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
						r.Metrics.CertificateIssues.WithLabelValues(container.Name, pod.Namespace, pod.Name, cert.Certificate.Subject.String(), fingerprint, n.Reason, "error").Set(float64(1))
					} else if n.Level == analyse.NoteLevelWarn {
						numWarn++
						r.Metrics.CertificateIssues.WithLabelValues(container.Name, pod.Namespace, pod.Name, cert.Certificate.Subject.String(), fingerprint, n.Reason, "warn").Set(float64(1))
					}
				}
				logger.Info(fmt.Sprintf("Certificate %s, Fingerprint: %s", cert.Certificate.Subject, fingerprint))
			}
		}
		r.Metrics.CertificateIssuesTotal.WithLabelValues(container.Name, pod.Namespace, pod.Name).Set(float64(numIssues))
		r.Metrics.CertificateWarningsTotal.WithLabelValues(container.Name, pod.Namespace, pod.Name).Set(float64(numWarn))
		r.Metrics.CertificateErrorsTotal.WithLabelValues(container.Name, pod.Namespace, pod.Name).Set(float64(numError))
		r.Metrics.CertificateFoundTotal.WithLabelValues(container.Name, pod.Namespace, pod.Name).Set(float64(len(parsedCertificates.Found)))
		r.Metrics.PartialCertificatesFoundTotal.WithLabelValues(container.Name, pod.Namespace, pod.Name).Set(float64(len(parsedCertificates.Partials)))
		logger.Info(fmt.Sprintf("Found %d certificates total, of which %d had issues", len(parsedCertificates.Found), numIssues))

		if len(parsedCertificates.Partials) > 0 {
			for _, p := range parsedCertificates.Partials {
				r.Metrics.PartialCertificateIssues.WithLabelValues(container.Name, pod.Namespace, pod.Name, p.Location, p.Reason).Set(float64(1))
				logger.Info(fmt.Sprintf("Partial certificate found in file %s: %s", p.Location, p.Reason))
			}
		}
	}

	logger.Info(fmt.Sprintf("Finished reconciling Pod: %s/%s", pod.Namespace, pod.Name))
	logger.Info(fmt.Sprintf("Waiting for Reconcile time: %s", r.RequeueTime))
	// Ensure the controller is requeued to run again after the specified reconcile time
	return ctrl.Result{RequeueAfter: r.RequeueTime}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}
