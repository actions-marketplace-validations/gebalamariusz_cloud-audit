# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-03

### Added

- Initial release
- CLI interface with `scan` and `version` commands
- 17 AWS security, cost, and reliability checks:
  - **IAM:** Root MFA, user MFA, access key rotation, unused access keys
  - **S3:** Public buckets, encryption at rest, versioning
  - **EC2:** Public AMIs, unencrypted EBS volumes, stopped instances
  - **VPC:** Default VPC usage, open security groups, flow logs
  - **RDS:** Public instances, encryption at rest, Multi-AZ
  - **EIP:** Unattached Elastic IPs
- Health score (0-100) based on finding severity
- HTML report with dark-mode design
- JSON output for CI/CD integration
- Docker image support
- Rich terminal UI with progress bar and color-coded findings

[Unreleased]: https://github.com/gebalamariusz/cloud-audit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gebalamariusz/cloud-audit/releases/tag/v0.1.0
