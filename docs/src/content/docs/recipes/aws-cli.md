---
title: 'AWS CLI'
description: Restrict destructive AWS operations, protect production environments, and enforce safe defaults.
sidebar:
  order: 3
---

This recipe shows how to configure runok to guard against accidental or unauthorized AWS CLI operations, especially in production environments.

## Complete Example

```yaml
# yaml-language-server: $schema=https://runok.fohte.net/schema/runok.schema.json

defaults:
  action: ask

rules:
  # Read-only operations — always allowed
  - allow: 'aws sts get-caller-identity'
  - allow: 'aws s3 ls *'
  - allow: 'aws ec2 describe-* *'
  - allow: 'aws iam list-* *'
  - allow: 'aws logs get-* *'
  - allow: 'aws logs describe-* *'
  - allow: 'aws cloudformation describe-* *'
  - allow: 'aws cloudformation list-* *'

  # Block all operations in production
  - deny: 'aws *'
    when: "env.AWS_PROFILE == 'production'"
    message: "All AWS operations are blocked when AWS_PROFILE is 'production'. Switch to a non-production profile."

  # Destructive operations — blocked
  - deny: 'aws ec2 terminate-instances *'
    message: 'Terminating EC2 instances requires manual confirmation in the AWS console.'

  - deny: 'aws s3 rb *'
    message: 'Removing S3 buckets is not allowed via CLI.'

  - deny: 'aws s3 rm * --recursive *'
    message: 'Recursive S3 deletion is not allowed.'
    fix_suggestion: 'aws s3 rm s3://bucket/key'

  - deny: 'aws iam delete-* *'
    message: 'IAM deletion operations are not allowed via CLI.'

  - deny: 'aws rds delete-db-instance *'
    message: 'Deleting RDS instances requires manual confirmation in the AWS console.'

  - deny: 'aws cloudformation delete-stack *'
    message: 'Deleting CloudFormation stacks is not allowed via CLI.'
```

## How It Works

### Read-only operations

Commands that only read data (`describe-*`, `list-*`, `ls`, `get-caller-identity`) are safe and allowed without confirmation.

The `*` in patterns like `aws ec2 describe-* *` matches any subcommand starting with `describe-` and any arguments.

### Production environment protection

The `when` condition uses a CEL expression to check the `AWS_PROFILE` environment variable. When it is set to `production`, **all** AWS operations are denied — even read-only ones.

Because deny rules take priority over allow rules, the production deny rule overrides the read-only allow rules above it.

### Destructive operation blocks

Specific destructive operations are blocked with clear messages explaining why. The `fix_suggestion` field offers safer alternatives where applicable.

## Variations

### Allow read-only access in production

If you want to allow read-only operations even in production, add specific allow rules **without** the `when` condition. The deny rule with `when: "env.AWS_PROFILE == 'production'"` only applies when the condition is true, but remember that explicit deny always wins.

A better approach is to use separate config files:

```yaml
# runok.yml (base rules)
rules:
  - allow: 'aws sts get-caller-identity'
  - allow: 'aws s3 ls *'
  - allow: 'aws ec2 describe-* *'
```

```yaml
# runok.local.yml (personal overrides, git-ignored)
rules:
  - deny: 'aws *'
    when: "env.AWS_PROFILE == 'production'"
    message: 'Production access is restricted.'
```

Since deny always wins regardless of file order, the production guard remains effective.

### Restrict by AWS region

```yaml
rules:
  - deny: 'aws *'
    when: "env.AWS_DEFAULT_REGION == 'us-east-1'"
    message: "Operations in us-east-1 are restricted. Use your team's assigned region."
```

### Sandbox network access for AWS CLI

Combine rules with sandbox policies to restrict filesystem access while allowing network:

```yaml
definitions:
  sandbox:
    aws-sandbox:
      fs:
        writable: [./output, /tmp]
        deny:
          - '~/.ssh/**'
          - '.env*'
      network:
        allow: true

rules:
  - allow: 'aws s3 cp *'
    sandbox: aws-sandbox
```
