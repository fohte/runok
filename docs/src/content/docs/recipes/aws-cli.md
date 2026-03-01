---
title: 'AWS CLI'
description: Restrict destructive AWS operations, protect production environments, and enforce safe defaults.
sidebar:
  order: 4
---

This recipe shows how to configure runok to guard against accidental or unauthorized AWS CLI operations, especially in production environments.

## Complete Example

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json

defaults:
  action: ask

rules:
  # === deny rules ===

  # Block all operations in production
  - deny: 'aws *'
    when: "env.AWS_PROFILE == 'production'"
    message: "All AWS operations are blocked when AWS_PROFILE is 'production'."

  # Secret access — blocked
  - deny: 'aws secretsmanager get-secret-value *'
    message: 'Retrieving secret values via CLI is not allowed.'

  - deny: 'aws ssm get-parameter* * --with-decryption *'
    message: 'Decrypting SSM parameters via CLI is not allowed.'

  # Destructive operations — blocked
  - deny: 'aws * delete-* *'
    message: 'Deletion operations are not allowed via CLI.'

  - deny: 'aws * terminate-* *'
    message: 'Terminate operations are not allowed via CLI.'

  - deny: 'aws s3 rb *'
    message: 'Removing S3 buckets is not allowed via CLI.'

  - deny: 'aws s3 rm * --recursive *'
    message: 'Recursive S3 deletion is not allowed.'
    fix_suggestion: 'aws s3 rm s3://bucket/key'

  # === allow rules ===

  # Read-only operations — always allowed
  - allow: 'aws sts get-caller-identity'
  - allow: 'aws s3 ls *'
  - allow: 'aws * get-*|list-*|describe-* *'
```

## How It Works

### Read-only operations with glob patterns

```yaml
- allow: 'aws * get-*|list-*|describe-* *'
```

The [alternation](/pattern-syntax/alternation/) `get-*|list-*|describe-*` matches any subcommand starting with `get-`, `list-`, or `describe-` across all AWS services. The `*` before it matches the service name (e.g., `ec2`, `iam`, `logs`), and the `*` after it matches any arguments.

This single rule covers commands like:

- `aws ec2 describe-instances --filters ...`
- `aws iam list-roles`
- `aws logs get-log-events --log-group-name ...`

### Destructive operation blocks with glob patterns

```yaml
- deny: 'aws * delete-* *'
- deny: 'aws * terminate-* *'
```

The same glob approach works for deny rules. `delete-*` catches `delete-stack`, `delete-db-instance`, `delete-user`, etc. across all services. Since [deny rules always win](/rule-evaluation/priority-model/), these override the `get-*|list-*|describe-*` allow even if a subcommand somehow matched both.

### Production environment protection

The [`when` condition](/rule-evaluation/when-clause/) uses a CEL expression to check the `AWS_PROFILE` environment variable. When it is set to `production`, **all** AWS operations are denied — even read-only ones.

Because deny rules take priority over allow rules, the production deny rule overrides the allow rules.

### Secret access protection

`aws secretsmanager get-secret-value` and `aws ssm get-parameter --with-decryption` are blocked to prevent secrets from being exposed in terminal output or logs. The `get-parameter*` glob also matches `get-parameters` and `get-parameters-by-path`.

Note that `get-secret-value` is denied even though `get-*` is allowed — deny always wins.

## Variations

### Restrict by AWS region

```yaml
rules:
  - deny: 'aws *'
    when: "env.AWS_DEFAULT_REGION == 'us-east-1'"
    message: "Operations in us-east-1 are restricted. Use your team's assigned region."
```

### Sandbox network access for AWS CLI

Combine rules with [sandbox policies](/sandbox/overview/) to restrict filesystem access while allowing network:

```yaml
definitions:
  paths:
    sensitive:
      - '~/.ssh/**'
      - '.env*'

  sandbox:
    aws-sandbox:
      fs:
        writable: [./output, /tmp]
        deny:
          - '<path:sensitive>'
      network:
        allow: true

rules:
  - allow: 'aws s3 cp *'
    sandbox: aws-sandbox
```
