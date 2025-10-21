# Paranoia Controller Helm Chart Usage Examples

This document provides examples of how to use the Paranoia Helm chart in different scenarios.

## Quick Start (Local Development)

1. **Build the image locally:**
   ```bash
   docker build -t localhost/paranoia:latest .
   ```

2. **Install with default local settings:**
   ```bash
   helm install paranoia ./charts/paranoia
   ```

3. **Install with local development values:**
   ```bash
   helm install paranoia ./charts/paranoia -f ./charts/paranoia/values-local.yaml
   ```

## Configuration Examples

### Basic Production Configuration

Create a `values-prod.yaml` file:

```yaml
image:
  repository: ghcr.io/jetstack/paranoia
  tag: "v1.0.0"
  pullPolicy: IfNotPresent

controller:
  config:
    requeueTime: 30  # Less frequent reconciliation for production
    logLevel: "info"
    maxConcurrentReconciles: 3
    namespaceExclude:
      - kube-system
      - kube-public
      - istio-system

resources:
  limits:
    cpu: 1000m
    memory: 2Gi
  requests:
    cpu: 500m
    memory: 1Gi

metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    labels:
      release: prometheus-stack
```

### Debug Configuration

For troubleshooting issues:

```yaml
controller:
  config:
    logLevel: "debug"
    requeueTime: 2  # Faster reconciliation for debugging
    pprofServingAddress: "0.0.0.0:6060"  # Enable profiling
```

### High-Performance Configuration

For clusters with many pods:

```yaml
controller:
  config:
    maxConcurrentReconciles: 10
    imageCacheTimeout: "1h"  # Longer cache for performance
    cacheSyncPeriod: "2h"    # Less frequent full syncs

resources:
  limits:
    cpu: 2000m
    memory: 4Gi
  requests:
    cpu: 1000m
    memory: 2Gi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 5
  targetCPUUtilizationPercentage: 70
```

## Useful Commands

### Check deployment status:
```bash
kubectl get pods -l app.kubernetes.io/name=paranoia
kubectl logs -f deployment/paranoia
```

### Access metrics:
```bash
kubectl port-forward service/paranoia 8080:8080
curl http://localhost:8080/metrics
```

### Upgrade configuration:
```bash
helm upgrade paranoia ./charts/paranoia -f your-values.yaml
```

### Uninstall:
```bash
helm uninstall paranoia
```

## Troubleshooting

### Common Issues

1. **Image pull errors**: Ensure the image is built and available locally or in your registry
2. **RBAC issues**: Check that the service account has proper cluster permissions
3. **Resource limits**: Adjust memory/CPU limits based on your cluster size

### Enable debug logging:
```bash
helm upgrade paranoia ./charts/paranoia --set controller.config.logLevel=debug
```
