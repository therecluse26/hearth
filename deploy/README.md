# Hearth — Deployment Guide

This directory contains ready-to-use deployment artifacts for three environments:

| Method | Directory | Best for |
|---|---|---|
| Docker Compose | `docker-compose.yml` | Local development, single-host |
| systemd | `systemd/hearth.service` | VM / bare-metal |
| Helm | `helm/hearth/` | Kubernetes |

---

## Prerequisites

All methods share the same binary. Download from [GitHub Releases](https://github.com/hearth-rs/hearth/releases) or use the Docker image:

```
ghcr.io/hearth-rs/hearth:latest
```

---

## Docker Compose (local development)

### Setup

```bash
# 1. Copy and edit the example config
cp hearth.example.yaml hearth.yaml

# 2. Start the stack
docker compose -f deploy/docker-compose.yml up -d

# 3. Check health
curl http://localhost:8420/health
# → {"status":"ok"}
```

Services started:
- **Hearth** at `http://localhost:8420`
- **Mailpit** (SMTP capture) at `http://localhost:8025`

### Configuration

Edit `hearth.yaml` in the project root and restart:

```bash
docker compose -f deploy/docker-compose.yml restart hearth
```

### Persistent data

All data is stored in a Docker named volume (`hearth_data`). To wipe and start fresh:

```bash
docker compose -f deploy/docker-compose.yml down -v
```

### Environment variables

Create a `.env` file in the project root. The compose file loads it automatically:

```bash
# .env
SMTP_PASSWORD=s3cr3t
```

Reference variables in `hearth.yaml`:

```yaml
email:
  smtp:
    password: "${SMTP_PASSWORD}"
```

---

## systemd (VM / bare-metal)

### Installation

```bash
# 1. Install the binary
sudo install -m 755 hearth /usr/local/bin/hearth

# 2. Create the hearth user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin hearth

# 3. Create directories
sudo mkdir -p /var/lib/hearth /etc/hearth
sudo chown -R hearth:hearth /var/lib/hearth /etc/hearth

# 4. Install the config
sudo cp hearth.example.yaml /etc/hearth/hearth.yaml
sudo chown hearth:hearth /etc/hearth/hearth.yaml
sudo chmod 640 /etc/hearth/hearth.yaml

# 5. Install the unit file
sudo cp deploy/systemd/hearth.service /etc/systemd/system/
sudo systemctl daemon-reload

# 6. Enable and start
sudo systemctl enable --now hearth

# 7. Check status
sudo systemctl status hearth
curl http://localhost:8420/health
```

### Logs

```bash
sudo journalctl -u hearth -f
```

### TLS

Enable TLS in `/etc/hearth/hearth.yaml`:

```yaml
server:
  tls_cert_path: /etc/hearth/tls/server.crt
  tls_key_path:  /etc/hearth/tls/server.key
```

Then reload without downtime (Hearth handles `SIGHUP`):

```bash
sudo systemctl kill --signal=SIGHUP hearth
```

### Security hardening

The unit file ships with these restrictions enabled by default:

- `NoNewPrivileges` — prevents privilege escalation via setuid
- `ProtectSystem=strict` — mounts `/usr`, `/boot`, `/etc` read-only
- `ProtectHome=true` — hides `/home` and `/root`
- `PrivateTmp=true` — isolated `/tmp`
- `PrivateDevices=true` — no raw device access
- `MemoryDenyWriteExecute=true` — enforces W^X
- `SystemCallFilter=@system-service` — restricts available syscalls
- `CapabilityBoundingSet=` — drops all capabilities (port 8420 doesn't need `CAP_NET_BIND_SERVICE`)

---

## Helm (Kubernetes)

### Prerequisites

- Kubernetes ≥ 1.24
- Helm ≥ 3.10
- A default `StorageClass` (for the PVC)

### Quick install

```bash
helm install hearth ./deploy/helm/hearth \
  --namespace hearth \
  --create-namespace \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=auth.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix
```

### Upgrade

```bash
helm upgrade hearth ./deploy/helm/hearth --namespace hearth
```

### Values reference

| Key | Default | Description |
|---|---|---|
| `image.repository` | `ghcr.io/hearth-rs/hearth` | Image repository |
| `image.tag` | Chart `appVersion` | Image tag |
| `replicaCount` | `1` | Pod count (see note on stateful scaling) |
| `persistence.enabled` | `true` | Enable PVC for data |
| `persistence.size` | `10Gi` | PVC size |
| `persistence.storageClassName` | `""` (cluster default) | StorageClass name |
| `ingress.enabled` | `false` | Create Ingress |
| `ingress.className` | `""` | IngressClass name |
| `config.*` | see `values.yaml` | Hearth YAML config |
| `secret.tlsCert` | `""` | PEM TLS certificate |
| `secret.tlsKey` | `""` | PEM TLS private key |
| `secret.env` | `{}` | Injected as env vars (e.g. `SMTP_PASSWORD`) |
| `resources.requests.cpu` | `100m` | CPU request |
| `resources.requests.memory` | `128Mi` | Memory request |

Full reference: [`helm/hearth/values.yaml`](helm/hearth/values.yaml).

### Exposing with cert-manager

```yaml
# my-values.yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: auth.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: hearth-tls
      hosts:
        - auth.example.com

config:
  server:
    bind_address: "0.0.0.0"
    port: 8420
  oidc:
    issuer: "https://auth.example.com"
```

```bash
helm install hearth ./deploy/helm/hearth -f my-values.yaml -n hearth --create-namespace
```

### Providing secrets

Use `secret.env` to inject credentials referenced from `hearth.yaml`:

```yaml
# my-values.yaml
secret:
  env:
    SMTP_PASSWORD: "s3cr3t"
    SENDGRID_API_KEY: "SG.xxx"

config:
  email:
    transport: smtp
    smtp:
      password: "${SMTP_PASSWORD}"
```

### Scaling note

Hearth uses an embedded storage engine (WAL + SSTs on a PVC). Multiple replicas sharing a `ReadWriteOnce` volume is not supported. For high availability, use `ReadWriteMany` storage or a remote backend (roadmap item). The `autoscaling` value block is available but disabled by default.

### Uninstall

```bash
helm uninstall hearth -n hearth
# The PVC is NOT deleted by default — delete it manually if you want to wipe data:
kubectl delete pvc -n hearth -l app.kubernetes.io/name=hearth
```

---

## Configuration reference

All three deployment methods consume the same `hearth.yaml` format. See [`hearth.example.yaml`](../hearth.example.yaml) for the full annotated reference, or run:

```bash
hearth config --help
```
