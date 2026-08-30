#!/usr/bin/env bash
# aws-exposure-audit.sh — read-only, fail-closed AWS evidence collector.
#
# The shell layer collects structured AWS CLI output. The Node bridge owns all
# finding semantics, renderers and exit policy. Portable to macOS Bash 3.2.
set -uo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/aws-exposure-audit.sh [--profile NAME] [--region REGION] [--out DIR]

Options:
  --profile NAME       AWS CLI profile (default: normal AWS resolution)
  --region REGION      AWS region (default: AWS_REGION or us-east-1)
  --out DIR            Write the v2 report bundle and sanitized observations
  --report-name NAME   Report basename (default: aws-report)
  --fail-on LEVEL      critical, high, medium, low, or never (default: high)
EOF
}

PROFILE=""
REGION="${AWS_REGION:-us-east-1}"
OUT_DIR=""
REPORT_NAME="aws-report"
FAIL_ON="high"
AWS_BIN="${WEBAPP_SECURITY_AWS_BIN:-aws}"

while [ $# -gt 0 ]; do
  case "$1" in
    --profile|--region|--out|--report-name|--fail-on)
      [ $# -ge 2 ] || { echo "error: $1 requires a value" >&2; exit 2; }
      case "$1" in
        --profile) PROFILE="$2";;
        --region) REGION="$2";;
        --out) OUT_DIR="$2";;
        --report-name) REPORT_NAME="$2";;
        --fail-on) FAIL_ON="$2";;
      esac
      shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "error: unknown arg: $1" >&2; exit 2;;
  esac
done

case "$REGION" in ''|*[!A-Za-z0-9._-]*) echo "error: --region contains unsupported characters" >&2; exit 2;; esac
case "$REPORT_NAME" in ''|*[!A-Za-z0-9._-]*) echo "error: --report-name contains unsupported characters" >&2; exit 2;; esac
case "$FAIL_ON" in critical|high|medium|low|never) ;; *) echo "error: --fail-on is invalid" >&2; exit 2;; esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
QUERY="$SCRIPT_DIR/aws-json-query.mjs"
BRIDGE="$SCRIPT_DIR/aws-exposure-report.mjs"
command -v node >/dev/null 2>&1 || { echo "error: node is required" >&2; exit 2; }

OBS_FILE="$(mktemp "${TMPDIR:-/tmp}/webapp-security-aws.XXXXXX")" || exit 2
chmod 600 "$OBS_FILE" || exit 2
trap 'rm -f "$OBS_FILE"' EXIT

record() {
  rule="$1" state="$2" subject="$3" message="$4"
  subject64="$(printf '%s' "$subject" | base64 | tr -d '\n')"
  message64="$(printf '%s' "$message" | base64 | tr -d '\n')"
  printf '%s\t%s\t%s\t%s\n' "$rule" "$state" "$subject64" "$message64" >> "$OBS_FILE"
}

resource_ref() {
  printf '%s' "$2" | node "$QUERY" hash "$1"
}

all_rules() {
  node "$BRIDGE" --list-rules
}

record_all_unknown() {
  message="$1"
  while IFS= read -r rule; do
    [ -n "$rule" ] && record "$rule" unknown "$rule" "$message"
  done <<EOF
$(all_rules)
EOF
}

emit() {
  set -- node "$BRIDGE" --observations "$OBS_FILE" --region "$REGION" \
    --account "${ACCOUNT:-unavailable}" --report-name "$REPORT_NAME" --fail-on "$FAIL_ON"
  if [ -n "$OUT_DIR" ]; then set -- "$@" --out "$OUT_DIR"; fi
  "$@"
}

if ! command -v "$AWS_BIN" >/dev/null 2>&1; then
  record_all_unknown "AWS CLI is unavailable; no AWS posture conclusion is possible"
  emit
  exit $?
fi

AWS=("$AWS_BIN")
[ -n "$PROFILE" ] && AWS+=(--profile "$PROFILE")
AWS+=(--region "$REGION" --output json --no-cli-pager)
RUN_OUT=""
RUN_KIND=""

fetch() {
  desc="$1"; shift
  if RUN_OUT="$("${AWS[@]}" "$@" 2>&1)"; then
    if printf '%s' "$RUN_OUT" | node "$QUERY" validate >/dev/null 2>&1; then
      RUN_KIND="ok"
      return 0
    fi
    RUN_KIND="malformed"
    RUN_OUT=""
    return 1
  fi
  RUN_KIND="denied"
  return 1
}

unknown_message() {
  if [ "$RUN_KIND" = "malformed" ]; then
    printf '%s' "$1 returned malformed JSON; evidence is unavailable"
  else
    printf '%s' "$1 failed; AWS CLI error details withheld"
  fi
}

query() {
  printf '%s' "$RUN_OUT" | node "$QUERY" "$@" 2>/dev/null
}

unknown_rules() {
  message="$1" subject="$2"; shift 2
  for rule in "$@"; do record "$rule" unknown "$subject" "$message"; done
}

not_applicable_rules() {
  message="$1" subject="$2"; shift 2
  for rule in "$@"; do record "$rule" not_applicable "$subject" "$message"; done
}

record aws-cli-capability passed aws-cli "AWS CLI is available and executable"

# Caller identity is the scope anchor. A denial or malformed response leaves every
# posture rule unknown; it does not fabricate a security failure.
if ! fetch "sts get-caller-identity" sts get-caller-identity --query '[Account,Arn]'; then
  message="$(unknown_message 'sts get-caller-identity')"
  record aws-caller-identity unknown caller "$message"
  while IFS= read -r rule; do
    case "$rule" in aws-cli-capability|aws-caller-identity) ;; *) record "$rule" unknown "$rule" "caller identity unavailable; check was not run";; esac
  done <<EOF
$(all_rules)
EOF
  emit
  exit $?
fi
identity="$(query tuple 2)" || identity=""
if [ -z "$identity" ]; then
  RUN_KIND="malformed"
  message="$(unknown_message 'sts get-caller-identity')"
  record aws-caller-identity unknown caller "$message"
  while IFS= read -r rule; do
    case "$rule" in aws-cli-capability|aws-caller-identity) ;; *) record "$rule" unknown "$rule" "caller identity unavailable; check was not run";; esac
  done <<EOF
$(all_rules)
EOF
  emit
  exit $?
fi
ACCOUNT="$(printf '%s' "$identity" | awk -F '\t' '{print $1}')"
case "$ACCOUNT" in ''|*[!0-9]*)
  record aws-caller-identity unknown caller "sts get-caller-identity returned an invalid account identifier"
  while IFS= read -r rule; do
    case "$rule" in aws-cli-capability|aws-caller-identity) ;; *) record "$rule" unknown "$rule" "caller identity unavailable; check was not run";; esac
  done <<EOF
$(all_rules)
EOF
  emit
  exit $?
  ;;
esac
record aws-caller-identity passed caller "AWS caller identity returned a valid account scope"

# IAM root posture.
if fetch "iam get-account-summary" iam get-account-summary --query '[SummaryMap.AccountMFAEnabled,SummaryMap.AccountAccessKeysPresent,SummaryMap.Users]'; then
  summary="$(query tuple 3)" || summary=""
  if [ -z "$summary" ]; then
    unknown_rules "iam get-account-summary returned an unexpected shape" account aws-root-mfa aws-root-access-keys
  else
    root_mfa="$(printf '%s' "$summary" | awk -F '\t' '{print $1}')"
    root_keys="$(printf '%s' "$summary" | awk -F '\t' '{print $2}')"
    case "$root_mfa" in 1) record aws-root-mfa passed account "root account has MFA enabled";; 0) record aws-root-mfa failed account "root account has no MFA";; *) record aws-root-mfa unknown account "root MFA value is malformed";; esac
    case "$root_keys" in 0) record aws-root-access-keys passed account "root account has no access keys";; 1) record aws-root-access-keys failed account "root account has access keys";; *) record aws-root-access-keys unknown account "root access-key value is malformed";; esac
  fi
else
  message="$(unknown_message 'iam get-account-summary')"
  unknown_rules "$message" account aws-root-mfa aws-root-access-keys
fi

# IAM users and access keys.
if fetch "iam list-users" iam list-users --query 'Users[].UserName'; then
  users="$(query list)" || users="__MALFORMED__"
  if [ "$users" = "__MALFORMED__" ]; then
    unknown_rules "iam list-users returned an unexpected shape" iam-users aws-iam-user-mfa aws-iam-access-key-age
  elif [ -z "$users" ]; then
    not_applicable_rules "no IAM users were returned" iam-users aws-iam-user-mfa aws-iam-access-key-age
  else
    while IFS= read -r user; do
      [ -z "$user" ] && continue
      user_ref="$(resource_ref iam-user "$user")"
      if fetch "iam list-mfa-devices" iam list-mfa-devices --user-name "$user" --query 'length(MFADevices)'; then
        mfa_count="$(query scalar)" || mfa_count=""
        case "$mfa_count" in ''|*[!0-9]*) record aws-iam-user-mfa unknown "$user_ref" "IAM MFA response is malformed";; 0) record aws-iam-user-mfa failed "$user_ref" "an IAM user has no MFA device";; *) record aws-iam-user-mfa passed "$user_ref" "IAM user has an MFA device";; esac
      else
        record aws-iam-user-mfa unknown "$user_ref" "$(unknown_message 'iam list-mfa-devices')"
      fi
      if fetch "iam list-access-keys" iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[?Status==`Active`].[AccessKeyId,CreateDate]'; then
        keys="$(query rows 2)" || keys="__MALFORMED__"
        if [ "$keys" = "__MALFORMED__" ]; then
          record aws-iam-access-key-age unknown "$user_ref" "IAM access-key response is malformed"
        elif [ -z "$keys" ]; then
          record aws-iam-access-key-age passed "$user_ref" "IAM user has no active access keys"
        else
          while IFS="$(printf '\t')" read -r key_id created; do
            [ -z "$key_id" ] && continue
            key_ref="$(resource_ref iam-key "$key_id")"
            created_epoch="$(date -u -j -f '%Y-%m-%dT%H:%M:%S' "${created%%+*}" +%s 2>/dev/null || date -u -d "$created" +%s 2>/dev/null || true)"
            if [ -z "$created_epoch" ]; then
              record aws-iam-access-key-age unknown "$key_ref" "IAM access-key creation date is malformed"
            else
              age=$(( ( $(date -u +%s) - created_epoch ) / 86400 ))
              if [ "$age" -gt 90 ]; then record aws-iam-access-key-age failed "$key_ref" "an active IAM access key is older than 90 days"; else record aws-iam-access-key-age passed "$key_ref" "active IAM access key is no older than 90 days"; fi
            fi
          done <<EOF
$keys
EOF
        fi
      else
        record aws-iam-access-key-age unknown "$user_ref" "$(unknown_message 'iam list-access-keys')"
      fi
    done <<EOF
$users
EOF
  fi
else
  message="$(unknown_message 'iam list-users')"
  unknown_rules "$message" iam-users aws-iam-user-mfa aws-iam-access-key-age
fi

# Customer-managed attached policies.
if fetch "iam list-policies" iam list-policies --scope Local --only-attached --query 'Policies[].[PolicyName,Arn]'; then
  policies="$(query rows 2)" || policies="__MALFORMED__"
  if [ "$policies" = "__MALFORMED__" ]; then
    record aws-iam-customer-policy-wildcard unknown iam-policies "iam list-policies returned an unexpected shape"
  elif [ -z "$policies" ]; then
    record aws-iam-customer-policy-wildcard not_applicable iam-policies "no attached customer-managed policies were returned"
  else
    while IFS="$(printf '\t')" read -r _ policy_arn; do
      [ -z "$policy_arn" ] && continue
      policy_ref="$(resource_ref iam-policy "$policy_arn")"
      if ! fetch "iam get-policy" iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId'; then
        record aws-iam-customer-policy-wildcard unknown "$policy_ref" "$(unknown_message 'iam get-policy')"; continue
      fi
      version_id="$(query scalar)" || version_id=""
      if [ -z "$version_id" ] || [ "$version_id" = "None" ]; then
        record aws-iam-customer-policy-wildcard unknown "$policy_ref" "IAM policy version is malformed"; continue
      fi
      if ! fetch "iam get-policy-version" iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query 'PolicyVersion.Document'; then
        record aws-iam-customer-policy-wildcard unknown "$policy_ref" "$(unknown_message 'iam get-policy-version')"; continue
      fi
      wildcard="$(query policy-wildcard)" || wildcard=""
      case "$wildcard" in true) record aws-iam-customer-policy-wildcard failed "$policy_ref" "an attached customer policy grants Action:* on Resource:*";; false) record aws-iam-customer-policy-wildcard passed "$policy_ref" "attached customer policy does not grant Action:* on Resource:*";; *) record aws-iam-customer-policy-wildcard unknown "$policy_ref" "IAM policy document is malformed";; esac
    done <<EOF
$policies
EOF
  fi
else
  record aws-iam-customer-policy-wildcard unknown iam-policies "$(unknown_message 'iam list-policies')"
fi

if fetch "iam get-account-password-policy" iam get-account-password-policy; then
  record aws-iam-password-policy passed account "IAM account password policy is configured"
elif printf '%s' "$RUN_OUT" | grep -q 'NoSuchEntity'; then
  record aws-iam-password-policy failed account "no IAM account password policy is configured"
else
  record aws-iam-password-policy unknown account "$(unknown_message 'iam get-account-password-policy')"
fi

# Network exposure.
SENSITIVE_PORTS="22 23 445 3389 3306 5432 27017 6379 9200 9300 5601 11211 8080 8000 5000"
if fetch "ec2 describe-security-groups" ec2 describe-security-groups --query 'SecurityGroups[].[GroupId,GroupName]'; then
  groups="$(query rows 2)" || groups="__MALFORMED__"
  if [ "$groups" = "__MALFORMED__" ]; then
    record aws-security-group-sensitive-exposure unknown security-groups "security-group inventory is malformed"
  elif [ -z "$groups" ]; then
    record aws-security-group-sensitive-exposure not_applicable security-groups "no security groups were returned"
  else
    while IFS="$(printf '\t')" read -r group_id _; do
      [ -z "$group_id" ] && continue
      group_ref="$(resource_ref security-group "$group_id")"
      if ! fetch "ec2 describe-security-groups ingress" ec2 describe-security-groups --group-ids "$group_id" --query 'SecurityGroups[].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`) || contains(Ipv6Ranges[].CidrIpv6, `::/0`)].[IpProtocol,FromPort,ToPort]'; then
        record aws-security-group-sensitive-exposure unknown "$group_ref" "$(unknown_message 'ec2 describe-security-groups ingress')"; continue
      fi
      ingress="$(query rows 3)" || ingress="__MALFORMED__"
      if [ "$ingress" = "__MALFORMED__" ]; then
        record aws-security-group-sensitive-exposure unknown "$group_ref" "security-group ingress response is malformed"; continue
      fi
      exposed=0
      while IFS="$(printf '\t')" read -r protocol from_port to_port; do
        [ -z "$protocol" ] && continue
        if [ "$protocol" = "-1" ]; then
          record aws-security-group-sensitive-exposure failed "$group_ref" "a security group allows all protocols and ports from the internet"; exposed=1; continue
        fi
        case "$from_port:$to_port" in *[!0-9:]*) continue;; esac
        for port in $SENSITIVE_PORTS; do
          if [ "$from_port" -le "$port" ] && [ "$to_port" -ge "$port" ]; then
            record aws-security-group-sensitive-exposure failed "$group_ref-port-$port" "a security group exposes sensitive port $port to the internet"; exposed=1
          fi
        done
      done <<EOF
$ingress
EOF
      [ "$exposed" -eq 1 ] || record aws-security-group-sensitive-exposure passed "$group_ref" "security group has no detected internet-exposed sensitive port"
    done <<EOF
$groups
EOF
  fi
else
  record aws-security-group-sensitive-exposure unknown security-groups "$(unknown_message 'ec2 describe-security-groups')"
fi

if fetch "ec2 describe-flow-logs" ec2 describe-flow-logs --query 'FlowLogs[].FlowLogId'; then
  flow_logs="$(query list)" || flow_logs="__MALFORMED__"
  if [ "$flow_logs" = "__MALFORMED__" ]; then record aws-vpc-flow-logs unknown vpc "flow-log response is malformed"; elif [ -z "$flow_logs" ]; then record aws-vpc-flow-logs failed vpc "no VPC flow logs are configured"; else record aws-vpc-flow-logs passed vpc "one or more VPC flow logs are configured"; fi
else
  record aws-vpc-flow-logs unknown vpc "$(unknown_message 'ec2 describe-flow-logs')"
fi

# Compute.
if fetch "ec2 describe-instances" ec2 describe-instances --query 'Reservations[].Instances[?State.Name==`running`].[InstanceId,MetadataOptions.HttpTokens,PublicIpAddress]'; then
  instances="$(query rows 3)" || instances="__MALFORMED__"
  if [ "$instances" = "__MALFORMED__" ]; then
    record aws-ec2-imdsv2 unknown ec2-instances "EC2 instance response is malformed"
  elif [ -z "$instances" ]; then
    record aws-ec2-imdsv2 not_applicable ec2-instances "no running EC2 instances were returned"
  else
    while IFS="$(printf '\t')" read -r instance_id tokens _; do
      instance_ref="$(resource_ref ec2-instance "$instance_id")"
      if [ "$tokens" = "required" ]; then record aws-ec2-imdsv2 passed "$instance_ref" "EC2 instance requires IMDSv2"; elif [ -n "$tokens" ] && [ "$tokens" != "None" ]; then record aws-ec2-imdsv2 failed "$instance_ref" "EC2 instance permits IMDSv1"; else record aws-ec2-imdsv2 unknown "$instance_ref" "EC2 metadata-token response is malformed"; fi
    done <<EOF
$instances
EOF
  fi
else
  record aws-ec2-imdsv2 unknown ec2-instances "$(unknown_message 'ec2 describe-instances')"
fi

if fetch "ec2 get-ebs-encryption-by-default" ec2 get-ebs-encryption-by-default --query 'EbsEncryptionByDefault'; then
  value="$(query scalar)" || value=""
  case "$value" in true|True) record aws-ebs-encryption-default passed account "EBS encryption by default is enabled";; false|False) record aws-ebs-encryption-default failed account "EBS encryption by default is disabled";; *) record aws-ebs-encryption-default unknown account "EBS encryption response is malformed";; esac
else record aws-ebs-encryption-default unknown account "$(unknown_message 'ec2 get-ebs-encryption-by-default')"; fi

for spec in "aws-public-ebs-snapshot|ec2 describe-snapshots|Snapshots|--owner-ids $ACCOUNT --restorable-by-user-ids all --query length(Snapshots)" "aws-public-ami|ec2 describe-images|AMIs|--owners $ACCOUNT --filters Name=is-public,Values=true --query length(Images)"; do
  rule="${spec%%|*}"; rest="${spec#*|}"; desc="${rest%%|*}"; rest="${rest#*|}"; label="${rest%%|*}"; command_args="${rest#*|}"
  # shellcheck disable=SC2086
  if fetch "$desc" $desc $command_args; then
    value="$(query scalar)" || value=""
    case "$value" in ''|*[!0-9]*) record "$rule" unknown account "$label count is malformed";; 0) record "$rule" passed account "no public $label were returned";; *) record "$rule" failed account "one or more public $label were returned";; esac
  else record "$rule" unknown account "$(unknown_message "$desc")"; fi
done

# S3 account and bucket posture.
if fetch "s3control get-public-access-block" s3control get-public-access-block --account-id "$ACCOUNT" --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]'; then
  pab="$(query tuple 4)" || pab=""
  if [ -z "$pab" ]; then record aws-s3-account-public-access-block unknown account "account public-access-block response is malformed"; elif printf '%s' "$pab" | grep -qi false; then record aws-s3-account-public-access-block failed account "account-level S3 Block Public Access is not fully enabled"; else record aws-s3-account-public-access-block passed account "account-level S3 Block Public Access is fully enabled"; fi
elif printf '%s' "$RUN_OUT" | grep -q 'NoSuchPublicAccessBlockConfiguration'; then
  record aws-s3-account-public-access-block failed account "no account-level S3 Block Public Access configuration exists"
else record aws-s3-account-public-access-block unknown account "$(unknown_message 's3control get-public-access-block')"; fi

if fetch "s3api list-buckets" s3api list-buckets --query 'Buckets[].Name'; then
  buckets="$(query list)" || buckets="__MALFORMED__"
  if [ "$buckets" = "__MALFORMED__" ]; then
    unknown_rules "bucket inventory is malformed" s3-buckets aws-s3-bucket-public-access-block aws-s3-public-policy aws-s3-default-encryption
  elif [ -z "$buckets" ]; then
    not_applicable_rules "no S3 buckets were returned" s3-buckets aws-s3-bucket-public-access-block aws-s3-public-policy aws-s3-default-encryption
  else
    while IFS= read -r bucket; do
      [ -z "$bucket" ] && continue
      bucket_ref="$(resource_ref s3-bucket "$bucket")"
      if fetch "s3api get-public-access-block" s3api get-public-access-block --bucket "$bucket" --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]'; then
        value="$(query tuple 4)" || value=""
        if [ -z "$value" ]; then record aws-s3-bucket-public-access-block unknown "$bucket_ref" "bucket public-access-block response is malformed"; elif printf '%s' "$value" | grep -qi false; then record aws-s3-bucket-public-access-block failed "$bucket_ref" "bucket Block Public Access is not fully enabled"; else record aws-s3-bucket-public-access-block passed "$bucket_ref" "bucket Block Public Access is fully enabled"; fi
      elif printf '%s' "$RUN_OUT" | grep -q 'NoSuchPublicAccessBlockConfiguration'; then record aws-s3-bucket-public-access-block failed "$bucket_ref" "bucket has no Block Public Access configuration"; else record aws-s3-bucket-public-access-block unknown "$bucket_ref" "$(unknown_message 's3api get-public-access-block')"; fi

      if fetch "s3api get-bucket-policy-status" s3api get-bucket-policy-status --bucket "$bucket" --query 'PolicyStatus.IsPublic'; then
        value="$(query scalar)" || value=""
        case "$value" in true|True) record aws-s3-public-policy failed "$bucket_ref" "bucket policy is public";; false|False) record aws-s3-public-policy passed "$bucket_ref" "bucket policy is not public";; *) record aws-s3-public-policy unknown "$bucket_ref" "bucket-policy status response is malformed";; esac
      elif printf '%s' "$RUN_OUT" | grep -q 'NoSuchBucketPolicy'; then record aws-s3-public-policy passed "$bucket_ref" "bucket has no bucket policy"; else record aws-s3-public-policy unknown "$bucket_ref" "$(unknown_message 's3api get-bucket-policy-status')"; fi

      if fetch "s3api get-bucket-encryption" s3api get-bucket-encryption --bucket "$bucket" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm'; then
        value="$(query scalar)" || value=""
        if [ -n "$value" ] && [ "$value" != "None" ]; then record aws-s3-default-encryption passed "$bucket_ref" "bucket default encryption is configured"; else record aws-s3-default-encryption unknown "$bucket_ref" "bucket encryption response is malformed"; fi
      elif printf '%s' "$RUN_OUT" | grep -q 'ServerSideEncryptionConfigurationNotFoundError'; then record aws-s3-default-encryption failed "$bucket_ref" "bucket has no default encryption configuration"; else record aws-s3-default-encryption unknown "$bucket_ref" "$(unknown_message 's3api get-bucket-encryption')"; fi
    done <<EOF
$buckets
EOF
  fi
else
  message="$(unknown_message 's3api list-buckets')"
  unknown_rules "$message" s3-buckets aws-s3-bucket-public-access-block aws-s3-public-policy aws-s3-default-encryption
fi

# Databases.
if fetch "rds describe-db-instances" rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,PubliclyAccessible,StorageEncrypted,BackupRetentionPeriod,DeletionProtection]'; then
  databases="$(query rows 5)" || databases="__MALFORMED__"
  if [ "$databases" = "__MALFORMED__" ]; then
    unknown_rules "RDS response is malformed" rds aws-rds-public-access aws-rds-storage-encryption aws-rds-backups aws-rds-deletion-protection
  elif [ -z "$databases" ]; then
    not_applicable_rules "no RDS instances were returned" rds aws-rds-public-access aws-rds-storage-encryption aws-rds-backups aws-rds-deletion-protection
  else
    while IFS="$(printf '\t')" read -r database_id public encrypted backups deletion; do
      database_ref="$(resource_ref rds-instance "$database_id")"
      case "$public" in false|False) record aws-rds-public-access passed "$database_ref" "RDS instance is not publicly accessible";; true|True) record aws-rds-public-access failed "$database_ref" "RDS instance is publicly accessible";; *) record aws-rds-public-access unknown "$database_ref" "RDS public-access value is malformed";; esac
      case "$encrypted" in true|True) record aws-rds-storage-encryption passed "$database_ref" "RDS storage is encrypted";; false|False) record aws-rds-storage-encryption failed "$database_ref" "RDS storage is not encrypted";; *) record aws-rds-storage-encryption unknown "$database_ref" "RDS encryption value is malformed";; esac
      case "$backups" in ''|*[!0-9]*) record aws-rds-backups unknown "$database_ref" "RDS backup-retention value is malformed";; 0) record aws-rds-backups failed "$database_ref" "RDS automated backups are disabled";; *) record aws-rds-backups passed "$database_ref" "RDS automated backups are enabled";; esac
      case "$deletion" in true|True) record aws-rds-deletion-protection passed "$database_ref" "RDS deletion protection is enabled";; false|False) record aws-rds-deletion-protection failed "$database_ref" "RDS deletion protection is disabled";; *) record aws-rds-deletion-protection unknown "$database_ref" "RDS deletion-protection value is malformed";; esac
    done <<EOF
$databases
EOF
  fi
else message="$(unknown_message 'rds describe-db-instances')"; unknown_rules "$message" rds aws-rds-public-access aws-rds-storage-encryption aws-rds-backups aws-rds-deletion-protection; fi

if fetch "docdb describe-db-clusters" docdb describe-db-clusters --query 'DBClusters[].[DBClusterIdentifier,StorageEncrypted,DeletionProtection]'; then
  clusters="$(query rows 3)" || clusters="__MALFORMED__"
  if [ "$clusters" = "__MALFORMED__" ]; then unknown_rules "DocumentDB response is malformed" docdb aws-docdb-storage-encryption aws-docdb-deletion-protection
  elif [ -z "$clusters" ]; then not_applicable_rules "no DocumentDB clusters were returned" docdb aws-docdb-storage-encryption aws-docdb-deletion-protection
  else
    while IFS="$(printf '\t')" read -r cluster_id encrypted deletion; do
      cluster_ref="$(resource_ref docdb-cluster "$cluster_id")"
      case "$encrypted" in true|True) record aws-docdb-storage-encryption passed "$cluster_ref" "DocumentDB storage is encrypted";; false|False) record aws-docdb-storage-encryption failed "$cluster_ref" "DocumentDB storage is not encrypted";; *) record aws-docdb-storage-encryption unknown "$cluster_ref" "DocumentDB encryption value is malformed";; esac
      case "$deletion" in true|True) record aws-docdb-deletion-protection passed "$cluster_ref" "DocumentDB deletion protection is enabled";; false|False) record aws-docdb-deletion-protection failed "$cluster_ref" "DocumentDB deletion protection is disabled";; *) record aws-docdb-deletion-protection unknown "$cluster_ref" "DocumentDB deletion-protection value is malformed";; esac
    done <<EOF
$clusters
EOF
  fi
else message="$(unknown_message 'docdb describe-db-clusters')"; unknown_rules "$message" docdb aws-docdb-storage-encryption aws-docdb-deletion-protection; fi

# Edge and detection controls.
if fetch "cloudfront list-distributions" cloudfront list-distributions --query 'DistributionList.Items[].[Id,DomainName,WebACLId]'; then
  distributions="$(query rows 3)" || distributions="__MALFORMED__"
  if [ "$distributions" = "__MALFORMED__" ]; then record aws-cloudfront-waf unknown cloudfront "CloudFront response is malformed"
  elif [ -z "$distributions" ]; then record aws-cloudfront-waf not_applicable cloudfront "no CloudFront distributions were returned"
  else
    while IFS="$(printf '\t')" read -r distribution_id _ web_acl; do
      distribution_ref="$(resource_ref cloudfront-distribution "$distribution_id")"
      if [ -z "$web_acl" ] || [ "$web_acl" = "None" ]; then record aws-cloudfront-waf failed "$distribution_ref" "CloudFront distribution has no WAF web ACL attached"; else record aws-cloudfront-waf passed "$distribution_ref" "CloudFront distribution has a WAF web ACL attached"; fi
    done <<EOF
$distributions
EOF
  fi
else record aws-cloudfront-waf unknown cloudfront "$(unknown_message 'cloudfront list-distributions')"; fi

if fetch "elbv2 describe-load-balancers" elbv2 describe-load-balancers --query 'LoadBalancers[].[LoadBalancerArn,LoadBalancerName]'; then
  balancers="$(query rows 2)" || balancers="__MALFORMED__"
  if [ "$balancers" = "__MALFORMED__" ]; then record aws-alb-access-logs unknown load-balancers "load-balancer response is malformed"
  elif [ -z "$balancers" ]; then record aws-alb-access-logs not_applicable load-balancers "no application load balancers were returned"
  else
    while IFS="$(printf '\t')" read -r balancer_arn _; do
      balancer_ref="$(resource_ref load-balancer "$balancer_arn")"
      if fetch "elbv2 describe-load-balancer-attributes" elbv2 describe-load-balancer-attributes --load-balancer-arn "$balancer_arn" --query 'Attributes[?Key==`access_logs.s3.enabled`].Value | [0]'; then
        value="$(query scalar)" || value=""
        case "$value" in true) record aws-alb-access-logs passed "$balancer_ref" "load-balancer access logs are enabled";; false) record aws-alb-access-logs failed "$balancer_ref" "load-balancer access logs are disabled";; *) record aws-alb-access-logs unknown "$balancer_ref" "load-balancer logging response is malformed";; esac
      else record aws-alb-access-logs unknown "$balancer_ref" "$(unknown_message 'elbv2 describe-load-balancer-attributes')"; fi
    done <<EOF
$balancers
EOF
  fi
else record aws-alb-access-logs unknown load-balancers "$(unknown_message 'elbv2 describe-load-balancers')"; fi

if fetch "cloudtrail describe-trails" cloudtrail describe-trails --query 'trailList[].[Name,IsMultiRegionTrail,LogFileValidationEnabled]'; then
  trails="$(query rows 3)" || trails="__MALFORMED__"
  if [ "$trails" = "__MALFORMED__" ]; then
    unknown_rules "CloudTrail response is malformed" cloudtrail aws-cloudtrail-configured aws-cloudtrail-multiregion aws-cloudtrail-log-validation aws-cloudtrail-logging
  elif [ -z "$trails" ]; then
    record aws-cloudtrail-configured failed cloudtrail "no CloudTrail trail is configured"
    not_applicable_rules "no CloudTrail exists to evaluate" cloudtrail aws-cloudtrail-multiregion aws-cloudtrail-log-validation aws-cloudtrail-logging
  else
    record aws-cloudtrail-configured passed cloudtrail "one or more CloudTrail trails are configured"
    while IFS="$(printf '\t')" read -r trail_name multi_region validation; do
      trail_ref="$(resource_ref cloudtrail "$trail_name")"
      case "$multi_region" in true|True) record aws-cloudtrail-multiregion passed "$trail_ref" "CloudTrail is multi-region";; false|False) record aws-cloudtrail-multiregion failed "$trail_ref" "CloudTrail is not multi-region";; *) record aws-cloudtrail-multiregion unknown "$trail_ref" "CloudTrail multi-region value is malformed";; esac
      case "$validation" in true|True) record aws-cloudtrail-log-validation passed "$trail_ref" "CloudTrail log-file validation is enabled";; false|False) record aws-cloudtrail-log-validation failed "$trail_ref" "CloudTrail log-file validation is disabled";; *) record aws-cloudtrail-log-validation unknown "$trail_ref" "CloudTrail validation value is malformed";; esac
      if fetch "cloudtrail get-trail-status" cloudtrail get-trail-status --name "$trail_name" --query 'IsLogging'; then
        value="$(query scalar)" || value=""
        case "$value" in true|True) record aws-cloudtrail-logging passed "$trail_ref" "CloudTrail is logging";; false|False) record aws-cloudtrail-logging failed "$trail_ref" "CloudTrail is not currently logging";; *) record aws-cloudtrail-logging unknown "$trail_ref" "CloudTrail logging response is malformed";; esac
      else record aws-cloudtrail-logging unknown "$trail_ref" "$(unknown_message 'cloudtrail get-trail-status')"; fi
    done <<EOF
$trails
EOF
  fi
else message="$(unknown_message 'cloudtrail describe-trails')"; unknown_rules "$message" cloudtrail aws-cloudtrail-configured aws-cloudtrail-multiregion aws-cloudtrail-log-validation aws-cloudtrail-logging; fi

for spec in "aws-guardduty|guardduty list-detectors|DetectorIds|DetectorIds" "aws-config-recorder|configservice describe-configuration-recorders|ConfigurationRecorders|ConfigurationRecorders[].name" "aws-budgets|budgets describe-budgets|Budgets|Budgets[].BudgetName"; do
  rule="${spec%%|*}"; rest="${spec#*|}"; desc="${rest%%|*}"; rest="${rest#*|}"; label="${rest%%|*}"; expression="${rest#*|}"
  if [ "$rule" = "aws-budgets" ]; then
    if fetch "$desc" budgets describe-budgets --account-id "$ACCOUNT" --query "$expression"; then :; else record "$rule" unknown account "$(unknown_message "$desc")"; continue; fi
  else
    # shellcheck disable=SC2086
    if fetch "$desc" $desc --query "$expression"; then :; else record "$rule" unknown account "$(unknown_message "$desc")"; continue; fi
  fi
  values="$(query list)" || values="__MALFORMED__"
  if [ "$values" = "__MALFORMED__" ]; then record "$rule" unknown account "$label response is malformed"; elif [ -z "$values" ]; then record "$rule" failed account "no $label were returned"; else record "$rule" passed account "one or more $label were returned"; fi
done

emit
exit $?
