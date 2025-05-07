package controller

import (
	"testing"
	"time"

	"github.com/jetstack/paranoia/internal/metrics"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1" // Add this import
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPodReconciler_SetupWithManager_Pod(t *testing.T) {
	// Create a mock PodReconciler
	mockClient := fake.NewClientBuilder().Build()
	mockMetrics := &metrics.Metrics{}
	mockLog := logrus.NewEntry(logrus.New())
	mockScheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(mockScheme))
	reconciler := &PodReconciler{
		Client:             mockClient,
		Metrics:            mockMetrics,
		Scheme:             mockScheme,
		Log:                mockLog,
		ExcludedNamespaces: []string{"excluded-namespace"},
		RequeueTime:        time.Second * 10,
	}

	// Create a mock manager
	mockManager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: mockScheme,
	})
	require.NoError(t, err)
	require.NotNil(t, mockManager)

	// Call the SetupWithManager method
	err = reconciler.SetupWithManager(mockManager)

	// Assert the results
	require.NoError(t, err)
}
