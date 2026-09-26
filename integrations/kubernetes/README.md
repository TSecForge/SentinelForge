# Kubernetes API audit -> SentinelForge

kube-apiserver can push audit events straight to SentinelForge, with no shipper in between. It sends
`audit.k8s.io/v1 EventList` batches, which `/api/v1/ingest/kubernetes` accepts. It authenticates with a bearer token,
which SentinelForge accepts as the API key.

1. Copy [`audit-policy.yaml`](audit-policy.yaml) and [`audit-webhook.kubeconfig`](audit-webhook.kubeconfig) to the
   control-plane node, for example `/etc/kubernetes/audit/`, and put your `API_KEY` in the kubeconfig's `token`.
2. Add these flags to kube-apiserver (static pod manifest), and mount the directory into the pod:

   ```
   --audit-policy-file=/etc/kubernetes/audit/audit-policy.yaml
   --audit-webhook-config-file=/etc/kubernetes/audit/audit-webhook.kubeconfig
   --audit-webhook-batch-max-wait=5s
   ```

3. Set `?host=` in the kubeconfig's server URL to your cluster name. Audit events don't carry one.

On managed clusters (EKS, AKS, GKE) you can't set apiserver flags. Export the provider's audit log instead
(CloudWatch, Azure Monitor, Cloud Logging) and forward it with Fluent Bit or Vector (see `../`).

The policy logs Secrets at **Metadata** level only, so secret values are never sent anywhere.
