package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestHandlePodDelete(t *testing.T) {
	// Create a test metric
	testMetric := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test_metric",
		Help: "A test metric",
	}, []string{"pod_name", "namespace", "container_name"})

	// Register the metric
	prometheus.MustRegister(testMetric)
	defer prometheus.Unregister(testMetric)

	// Add a sample metric value
	testMetric.With(prometheus.Labels{
		"pod_name":       "test-pod",
		"namespace":      "test-namespace",
		"container_name": "test-container",
	}).Set(1)

	// Verify the metric exists
	if testutil.CollectAndCount(testMetric) != 1 {
		t.Fatalf("expected metric to exist before deletion")
	}

	// Create a MetricCleaner
	mc := NewMetricCleaner(testMetric)

	// Create a test Pod with multiple containers
	testPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "test-namespace",
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{Name: "test-container"},
				{Name: "another-container"},
			},
		},
	}

	// Call HandlePodDelete
	mc.HandlePodDelete(testPod)

	// Verify the metrics for all containers have been deleted
	if testutil.CollectAndCount(testMetric) != 0 {
		t.Fatalf("expected metrics to be deleted for all containers")
	}
}
