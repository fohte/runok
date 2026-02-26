---
title: 'Docker'
description: Enforce container security policies, restrict privileged operations, and control image sources.
sidebar:
  order: 4
---

This recipe shows how to configure runok to enforce Docker security policies — restricting privileged containers, controlling volume mounts, and guarding production deployments.

## Complete Example

```yaml
# yaml-language-server: $schema=https://runok.fohte.net/schema/runok.schema.json

defaults:
  action: ask

definitions:
  paths:
    sensitive:
      - '~/.ssh/**'
      - '~/.aws/**'
      - '.env*'
      - '/etc/shadow'
      - '/etc/passwd'

rules:
  # Read-only operations — always allowed
  - allow: 'docker ps *'
  - allow: 'docker images *'
  - allow: 'docker inspect *'
  - allow: 'docker logs *'
  - allow: 'docker stats *'
  - allow: 'docker info'
  - allow: 'docker version'

  # Build and development — allowed
  - allow: 'docker build *'
  - allow: 'docker compose up *'
  - allow: 'docker compose down *'
  - allow: 'docker compose logs *'
  - allow: 'docker run *'

  # Block privileged mode
  - deny: 'docker run --privileged *'
    message: 'Running containers in privileged mode is not allowed. Use specific --cap-add flags instead.'
    fix_suggestion: 'docker run --cap-add SYS_PTRACE ...'

  # Block host network mode
  - deny: 'docker run --network host *'
    message: 'Host networking exposes all host ports to the container.'
    fix_suggestion: 'docker run -p 8080:80 ...'

  # Block host PID namespace
  - deny: 'docker run --pid host *'
    message: 'Sharing the host PID namespace is not allowed.'

  # Block mounting the Docker socket
  - deny: 'docker run * -v /var/run/docker.sock:/var/run/docker.sock *'
    message: 'Mounting the Docker socket gives the container full control over the host Docker daemon.'

  # Push — require confirmation
  - ask: 'docker push *'

  # Dangerous operations — blocked
  - deny: 'docker system prune *'
    message: 'System prune removes all unused data. Use targeted cleanup instead.'
    fix_suggestion: 'docker image prune'

  - deny: 'docker rm -f *'
    message: 'Force removing containers can cause data loss.'
    fix_suggestion: 'docker stop <container> && docker rm <container>'
```

## How It Works

### Read-only operations

Inspection commands (`docker ps`, `docker images`, `docker logs`, etc.) are safe and always allowed.

### Build and development

Build and Compose operations are allowed for development workflows. The `docker run *` allow rule permits running containers — but the deny rules below it override it for specific dangerous flags.

### Security restrictions

The deny rules target specific Docker flags that pose security risks:

- **`--privileged`** — Gives the container almost full access to the host. Suggest `--cap-add` for specific capabilities instead.
- **`--network host`** — Shares the host network namespace, exposing all host services. Suggest explicit port mapping.
- **`--pid host`** — Shares the host PID namespace, allowing the container to see and signal host processes.
- **`-v /var/run/docker.sock:...`** — Mounting the Docker socket allows container escape.

### Destructive operations

- **`docker system prune`** — Removes all unused containers, networks, images, and optionally volumes. The suggestion is `docker image prune` for more targeted cleanup.
- **`docker rm -f`** — Force-removing containers can interrupt running processes and cause data loss.

## Variations

### Restrict image sources

Block pulling images from untrusted registries:

```yaml
rules:
  # Allow your organization's registry
  - allow: 'docker pull ghcr.io/your-org/* *'
  - allow: 'docker pull your-org.azurecr.io/* *'

  # Allow official images
  - allow: 'docker pull library/* *'

  # Block all other pulls
  - deny: 'docker pull *'
    message: 'Only images from approved registries are allowed.'
```

### Protect production deployments

```yaml
rules:
  - deny: 'docker compose * -f *production* *'
    message: 'Production deployments must go through CI/CD.'

  - deny: 'docker push *:latest'
    message: 'Pushing the :latest tag is not allowed. Use a versioned tag.'
    fix_suggestion: 'docker push your-image:v1.2.3'
```

### Restrict volume mounts

Block mounting sensitive host paths into containers:

```yaml
rules:
  - deny: 'docker run * -v <path:sensitive>:* *'
    message: 'Mounting sensitive host paths into containers is not allowed.'
```

This uses the `<path:sensitive>` reference to match against the `definitions.paths.sensitive` list, blocking mounts of `~/.ssh`, `~/.aws`, `.env` files, and other sensitive paths.
