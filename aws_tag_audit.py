#!/usr/bin/env python3
"""
aws_tag_audit.py - find AWS resources that are missing a required tag
(default: "Program") and then tag them with a value you supply.

  scan   Enumerate resources in every enabled region and write a CSV of the
         ones missing the tag (plus a full inventory CSV).
  apply  Read that CSV and add the tag. The value comes from you: fill the
         "Program" column in the CSV, answer a prompt for each resource
         (--interactive), or give one value for every row (--value).

Only dependency: boto3.  Python 3.8+.

Discovery uses two sources and merges them by ARN:
  1. Direct per-service enumeration (EC2, S3, RDS, Lambda, IAM, ...). This is
     the only reliable way to find resources that have NEVER been tagged.
  2. The Resource Groups Tagging API (tag:GetResources). Covers many more
     resource types, but only returns resources that have (or once had) tags.
"""

import argparse
import csv
import datetime as _dt
import difflib
import json
import os
import re
import shlex
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import boto3
    import botocore.session
    from botocore import xform_name
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError
except ImportError:  # pragma: no cover
    sys.exit("boto3 is required:  pip install boto3")

BOTO_CFG = Config(retries={"max_attempts": 10, "mode": "adaptive"}, connect_timeout=10, read_timeout=60)

# Where "global" services (IAM, Route 53) live in each partition.
HOME_REGION = {
    "aws": "us-east-1",
    "aws-us-gov": "us-gov-west-1",
    "aws-cn": "cn-north-1",
    "aws-iso": "us-iso-east-1",
    "aws-iso-b": "us-isob-east-1",
}

# Errors that just mean "you can't / this isn't here" - log and move on.
SKIP_CODES = {
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError",
    "OptInRequired", "UnrecognizedClientException", "InvalidClientTokenId",
    "SubscriptionRequiredException", "UnsupportedOperation", "InvalidAction",
}

# Allowed characters for tag values that work across all services.
TAG_VALUE_RE = re.compile(r"^[\w\s.:/=+\-@]*$", re.UNICODE)


# --------------------------------------------------------------------------- #
# Context / helpers
# --------------------------------------------------------------------------- #
class Ctx:
    def __init__(self, profile=None, region=None, workers=8):
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self._lock = threading.Lock()
        self._clients = {}
        self.workers = workers
        start_region = self.session.region_name or region
        if not start_region:
            sys.exit("No region configured. Pass --region (e.g. --region us-gov-west-1) or set AWS_DEFAULT_REGION.")
        self.start_region = start_region
        try:
            ident = self.client("sts", start_region).get_caller_identity()
        except Exception as e:  # noqa: BLE001
            if type(e).__name__ == "MissingDependencyException":
                sys.exit("This profile uses 'aws login' credentials, which boto3 can only read with an extra package:\n"
                         "    pip install \"botocore[crt]\"\n(%s)" % e)
            if type(e).__name__ in ("NoCredentialsError", "UnauthorizedSSOTokenError", "SSOTokenLoadError", "TokenRetrievalError"):
                sys.exit("Not logged in for this profile (%s). Run 'aws login' / 'aws sso login' with the same --profile first." % type(e).__name__)
            raise
        self.account = ident["Account"]
        self.caller_arn = ident["Arn"]
        self.partition = ident["Arn"].split(":")[1]
        self.home_region = HOME_REGION.get(self.partition, start_region)

    def client(self, service, region):
        # boto3 client creation is not thread-safe; clients themselves are.
        key = (service, region)
        with self._lock:
            if key not in self._clients:
                self._clients[key] = self.session.client(service, region_name=region, config=BOTO_CFG)
            return self._clients[key]

    def enabled_regions(self):
        resp = self.client("ec2", self.start_region).describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])


def paginate(client, op, key, **kwargs):
    """Yield items from list/describe calls, paginated or not."""
    if client.can_paginate(op):
        for page in client.get_paginator(op).paginate(**kwargs):
            for item in page.get(key, []) or []:
                yield item
    else:
        for item in getattr(client, op)(**kwargs).get(key, []) or []:
            yield item


def chunks(seq, n):
    seq = list(seq)
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def tag_list_to_dict(lst, k="Key", v="Value"):
    return {t[k]: t.get(v, "") for t in (lst or []) if k in t}


def res(service, rtype, region, rid, arn, tags, name=None, source="enum"):
    tags = tags or {}
    return {
        "service": service,
        "type": rtype,
        "region": region,
        "id": rid,
        "name": name or tags.get("Name") or "",
        "arn": arn,
        "tags": tags,
        "source": source,
    }


def err_code(e):
    if isinstance(e, ClientError):
        return e.response.get("Error", {}).get("Code", "ClientError")
    return type(e).__name__


# --------------------------------------------------------------------------- #
# Collectors.  Each is fn(ctx, region) -> iterable of res(...)
# scope "regional" runs once per region; "global" runs once total.
# --------------------------------------------------------------------------- #
COLLECTORS = []  # (name, service_group, scope, fn)


def collector(name, group=None, scope="regional"):
    def deco(fn):
        COLLECTORS.append((name, group or name.split(":")[0], scope, fn))
        return fn
    return deco


# ---- EC2 family -------------------------------------------------------------
def _ec2_simple(rtype, op, key, id_key, kwargs=None, acct=True, skip=None, tag_key="Tags", name_key=None):
    def fn(ctx, region):
        c = ctx.client("ec2", region)
        for it in paginate(c, op, key, **(kwargs or {})):
            rid = it.get(id_key)
            if not rid:
                continue
            arn = "arn:%s:ec2:%s:%s:%s/%s" % (ctx.partition, region, ctx.account if acct else "", rtype, rid)
            if skip and skip(it):
                ctx.skipped_arns.add(arn)
                continue
            tags = tag_list_to_dict(it.get(tag_key))
            yield res("ec2", rtype, region, rid, arn, tags, name=tags.get("Name") or (it.get(name_key) if name_key else None))
    return fn


def _state(field, *bad):
    return lambda it: (it.get(field) or "").lower() in bad


_EC2_SPECS = [
    ("volume", "describe_volumes", "Volumes", "VolumeId", {}, True, None, "Tags", None),
    ("snapshot", "describe_snapshots", "Snapshots", "SnapshotId", {"OwnerIds": ["self"]}, False, None, "Tags", None),
    ("image", "describe_images", "Images", "ImageId", {"Owners": ["self"]}, False, None, "Tags", "Name"),
    ("security-group", "describe_security_groups", "SecurityGroups", "GroupId", {}, True, None, "Tags", "GroupName"),
    ("vpc", "describe_vpcs", "Vpcs", "VpcId", {}, True, None, "Tags", None),
    ("subnet", "describe_subnets", "Subnets", "SubnetId", {}, True, None, "Tags", None),
    ("network-interface", "describe_network_interfaces", "NetworkInterfaces", "NetworkInterfaceId", {}, True, None, "TagSet", "Description"),
    ("elastic-ip", "describe_addresses", "Addresses", "AllocationId", {}, True, None, "Tags", "PublicIp"),
    ("internet-gateway", "describe_internet_gateways", "InternetGateways", "InternetGatewayId", {}, True, None, "Tags", None),
    ("natgateway", "describe_nat_gateways", "NatGateways", "NatGatewayId", {}, True, _state("State", "deleted", "deleting", "failed"), "Tags", None),
    ("route-table", "describe_route_tables", "RouteTables", "RouteTableId", {}, True, None, "Tags", None),
    ("network-acl", "describe_network_acls", "NetworkAcls", "NetworkAclId", {}, True, None, "Tags", None),
    ("dhcp-options", "describe_dhcp_options", "DhcpOptions", "DhcpOptionsId", {}, True, None, "Tags", None),
    ("key-pair", "describe_key_pairs", "KeyPairs", "KeyPairId", {}, True, None, "Tags", "KeyName"),
    ("launch-template", "describe_launch_templates", "LaunchTemplates", "LaunchTemplateId", {}, True, None, "Tags", "LaunchTemplateName"),
    ("vpc-endpoint", "describe_vpc_endpoints", "VpcEndpoints", "VpcEndpointId", {}, True, _state("State", "deleted", "deleting", "failed"), "Tags", "ServiceName"),
    ("transit-gateway", "describe_transit_gateways", "TransitGateways", "TransitGatewayId", {}, True, _state("State", "deleted", "deleting"), "Tags", None),
]
for _spec in _EC2_SPECS:
    collector("ec2:" + _spec[0], "ec2")(_ec2_simple(*_spec))


@collector("ec2:instance", "ec2")
def ec2_instances(ctx, region):
    c = ctx.client("ec2", region)
    for r in paginate(c, "describe_instances", "Reservations"):
        for i in r.get("Instances", []):
            rid = i["InstanceId"]
            arn = "arn:%s:ec2:%s:%s:instance/%s" % (ctx.partition, region, ctx.account, rid)
            if i.get("State", {}).get("Name") in ("terminated", "shutting-down"):
                ctx.skipped_arns.add(arn)
                continue
            yield res("ec2", "instance", region, rid, arn, tag_list_to_dict(i.get("Tags")))


# ---- Compute / containers ---------------------------------------------------
@collector("lambda")
def lambda_functions(ctx, region):
    c = ctx.client("lambda", region)
    for f in paginate(c, "list_functions", "Functions"):
        tags = c.list_tags(Resource=f["FunctionArn"]).get("Tags", {})
        yield res("lambda", "function", region, f["FunctionName"], f["FunctionArn"], tags, name=f["FunctionName"])


@collector("ecs")
def ecs_clusters(ctx, region):
    c = ctx.client("ecs", region)
    arns = list(paginate(c, "list_clusters", "clusterArns"))
    for chunk in chunks(arns, 100):
        for cl in c.describe_clusters(clusters=chunk, include=["TAGS"]).get("clusters", []):
            tags = tag_list_to_dict(cl.get("tags"), "key", "value")
            yield res("ecs", "cluster", region, cl["clusterName"], cl["clusterArn"], tags, name=cl["clusterName"])


@collector("eks")
def eks_clusters(ctx, region):
    c = ctx.client("eks", region)
    for name in paginate(c, "list_clusters", "clusters"):
        cl = c.describe_cluster(name=name)["cluster"]
        yield res("eks", "cluster", region, name, cl["arn"], cl.get("tags", {}), name=name)


@collector("ecr")
def ecr_repos(ctx, region):
    c = ctx.client("ecr", region)
    for r in paginate(c, "describe_repositories", "repositories"):
        tags = tag_list_to_dict(c.list_tags_for_resource(resourceArn=r["repositoryArn"]).get("tags"))
        yield res("ecr", "repository", region, r["repositoryName"], r["repositoryArn"], tags, name=r["repositoryName"])


@collector("autoscaling")
def asgs(ctx, region):
    c = ctx.client("autoscaling", region)
    for g in paginate(c, "describe_auto_scaling_groups", "AutoScalingGroups"):
        name = g["AutoScalingGroupName"]
        yield res("autoscaling", "autoScalingGroup", region, name, g["AutoScalingGroupARN"], tag_list_to_dict(g.get("Tags")), name=name)


# ---- Storage / databases ----------------------------------------------------
@collector("s3", scope="global")
def s3_buckets(ctx, _region):
    c = ctx.client("s3", ctx.home_region)
    for b in c.list_buckets().get("Buckets", []):
        name = b["Name"]
        try:
            loc = c.get_bucket_location(Bucket=name).get("LocationConstraint")
        except ClientError as e:
            ctx.scan_errors.append(("s3", name, err_code(e), str(e)))
            continue
        region = {None: ctx.home_region, "": ctx.home_region, "EU": "eu-west-1"}.get(loc, loc)
        if ctx.region_filter and region not in ctx.region_filter:
            continue
        try:
            tags = tag_list_to_dict(ctx.client("s3", region).get_bucket_tagging(Bucket=name).get("TagSet"))
        except ClientError as e:
            if err_code(e) != "NoSuchTagSet":
                ctx.scan_errors.append(("s3", name, err_code(e), str(e)))
                continue
            tags = {}
        yield res("s3", "bucket", region, name, "arn:%s:s3:::%s" % (ctx.partition, name), tags, name=name)


@collector("efs")
def efs(ctx, region):
    c = ctx.client("efs", region)
    for fs in paginate(c, "describe_file_systems", "FileSystems"):
        arn = fs.get("FileSystemArn") or "arn:%s:elasticfilesystem:%s:%s:file-system/%s" % (ctx.partition, region, ctx.account, fs["FileSystemId"])
        yield res("elasticfilesystem", "file-system", region, fs["FileSystemId"], arn, tag_list_to_dict(fs.get("Tags")), name=fs.get("Name"))


@collector("rds")
def rds(ctx, region):
    c = ctx.client("rds", region)
    for db in paginate(c, "describe_db_instances", "DBInstances"):
        i = db["DBInstanceIdentifier"]
        yield res("rds", "db", region, i, db["DBInstanceArn"], tag_list_to_dict(db.get("TagList")), name=i)
    for cl in paginate(c, "describe_db_clusters", "DBClusters"):
        i = cl["DBClusterIdentifier"]
        yield res("rds", "cluster", region, i, cl["DBClusterArn"], tag_list_to_dict(cl.get("TagList")), name=i)
    for s in paginate(c, "describe_db_snapshots", "DBSnapshots", SnapshotType="manual"):
        i = s["DBSnapshotIdentifier"]
        yield res("rds", "snapshot", region, i, s["DBSnapshotArn"], tag_list_to_dict(s.get("TagList")), name=i)


@collector("dynamodb")
def dynamodb(ctx, region):
    c = ctx.client("dynamodb", region)
    for t in paginate(c, "list_tables", "TableNames"):
        arn = "arn:%s:dynamodb:%s:%s:table/%s" % (ctx.partition, region, ctx.account, t)
        tags = tag_list_to_dict(c.list_tags_of_resource(ResourceArn=arn).get("Tags"))
        yield res("dynamodb", "table", region, t, arn, tags, name=t)


# ---- Messaging / app integration --------------------------------------------
@collector("sns")
def sns(ctx, region):
    c = ctx.client("sns", region)
    for t in paginate(c, "list_topics", "Topics"):
        arn = t["TopicArn"]
        tags = tag_list_to_dict(c.list_tags_for_resource(ResourceArn=arn).get("Tags"))
        name = arn.rsplit(":", 1)[-1]
        yield res("sns", "topic", region, name, arn, tags, name=name)


@collector("sqs")
def sqs(ctx, region):
    c = ctx.client("sqs", region)
    for url in paginate(c, "list_queues", "QueueUrls"):
        name = url.rstrip("/").rsplit("/", 1)[-1]
        arn = "arn:%s:sqs:%s:%s:%s" % (ctx.partition, region, ctx.account, name)
        tags = c.list_queue_tags(QueueUrl=url).get("Tags", {}) or {}
        r = res("sqs", "queue", region, name, arn, tags, name=name)
        r["url"] = url
        yield r


@collector("stepfunctions")
def sfn(ctx, region):
    c = ctx.client("stepfunctions", region)
    for sm in paginate(c, "list_state_machines", "stateMachines"):
        tags = tag_list_to_dict(c.list_tags_for_resource(resourceArn=sm["stateMachineArn"]).get("tags"), "key", "value")
        yield res("states", "stateMachine", region, sm["name"], sm["stateMachineArn"], tags, name=sm["name"])


# ---- Networking -------------------------------------------------------------
@collector("elbv2")
def elbv2(ctx, region):
    c = ctx.client("elbv2", region)
    items = []
    for lb in paginate(c, "describe_load_balancers", "LoadBalancers"):
        items.append(("loadbalancer", lb["LoadBalancerArn"], lb["LoadBalancerName"]))
    for tg in paginate(c, "describe_target_groups", "TargetGroups"):
        items.append(("targetgroup", tg["TargetGroupArn"], tg["TargetGroupName"]))
    for chunk in chunks(items, 20):
        td = c.describe_tags(ResourceArns=[a for _, a, _ in chunk]).get("TagDescriptions", [])
        tagmap = {d["ResourceArn"]: tag_list_to_dict(d.get("Tags")) for d in td}
        for rtype, arn, name in chunk:
            yield res("elasticloadbalancing", rtype, region, name, arn, tagmap.get(arn, {}), name=name)


@collector("elb")
def elb_classic(ctx, region):
    c = ctx.client("elb", region)
    names = [lb["LoadBalancerName"] for lb in paginate(c, "describe_load_balancers", "LoadBalancerDescriptions")]
    for chunk in chunks(names, 20):
        td = c.describe_tags(LoadBalancerNames=chunk).get("TagDescriptions", [])
        tagmap = {d["LoadBalancerName"]: tag_list_to_dict(d.get("Tags")) for d in td}
        for n in chunk:
            arn = "arn:%s:elasticloadbalancing:%s:%s:loadbalancer/%s" % (ctx.partition, region, ctx.account, n)
            yield res("elasticloadbalancing", "loadbalancer-classic", region, n, arn, tagmap.get(n, {}), name=n)


@collector("route53", scope="global")
def route53(ctx, _region):
    c = ctx.client("route53", ctx.home_region)
    zones = [(z["Id"].split("/")[-1], z["Name"]) for z in paginate(c, "list_hosted_zones", "HostedZones")]
    for chunk in chunks(zones, 10):
        sets = c.list_tags_for_resources(ResourceType="hostedzone", ResourceIds=[z for z, _ in chunk]).get("ResourceTagSets", [])
        tagmap = {s["ResourceId"]: tag_list_to_dict(s.get("Tags")) for s in sets}
        for zid, zname in chunk:
            arn = "arn:%s:route53:::hostedzone/%s" % (ctx.partition, zid)
            yield res("route53", "hostedzone", "global", zid, arn, tagmap.get(zid, {}), name=zname)


# ---- Security / management --------------------------------------------------
@collector("kms")
def kms(ctx, region):
    c = ctx.client("kms", region)
    for k in paginate(c, "list_keys", "Keys"):
        md = c.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
        if md.get("KeyManager") != "CUSTOMER" or md.get("KeyState") in ("PendingDeletion", "PendingReplicaDeletion"):
            ctx.skipped_arns.add(k["KeyArn"])  # AWS-managed or being deleted: can't be tagged
            continue
        tags = tag_list_to_dict(c.list_resource_tags(KeyId=k["KeyId"]).get("Tags"), "TagKey", "TagValue")
        yield res("kms", "key", region, k["KeyId"], k["KeyArn"], tags, name=md.get("Description") or k["KeyId"])


@collector("secretsmanager")
def secrets(ctx, region):
    c = ctx.client("secretsmanager", region)
    for s in paginate(c, "list_secrets", "SecretList"):
        yield res("secretsmanager", "secret", region, s["Name"], s["ARN"], tag_list_to_dict(s.get("Tags")), name=s["Name"])


@collector("logs")
def log_groups(ctx, region):
    c = ctx.client("logs", region)
    for lg in paginate(c, "describe_log_groups", "logGroups"):
        name = lg["logGroupName"]
        arn = lg.get("logGroupArn") or re.sub(r":\*$", "", lg.get("arn", ""))
        tags = c.list_tags_log_group(logGroupName=name).get("tags", {}) or {}
        yield res("logs", "log-group", region, name, arn, tags, name=name)


@collector("cloudformation")
def cfn(ctx, region):
    c = ctx.client("cloudformation", region)
    for s in paginate(c, "describe_stacks", "Stacks"):
        yield res("cloudformation", "stack", region, s["StackName"], s["StackId"], tag_list_to_dict(s.get("Tags")), name=s["StackName"])


@collector("iam:role", "iam", scope="global")
def iam_roles(ctx, _region):
    c = ctx.client("iam", ctx.home_region)
    for r in paginate(c, "list_roles", "Roles"):
        if r.get("Path", "").startswith("/aws-service-role/"):
            ctx.skipped_arns.add(r["Arn"])  # service-linked roles can't be tagged by you
            continue
        tags = tag_list_to_dict(c.list_role_tags(RoleName=r["RoleName"]).get("Tags"))
        yield res("iam", "role", "global", r["RoleName"], r["Arn"], tags, name=r["RoleName"])


@collector("iam:user", "iam", scope="global")
def iam_users(ctx, _region):
    c = ctx.client("iam", ctx.home_region)
    for u in paginate(c, "list_users", "Users"):
        tags = tag_list_to_dict(c.list_user_tags(UserName=u["UserName"]).get("Tags"))
        yield res("iam", "user", "global", u["UserName"], u["Arn"], tags, name=u["UserName"])


@collector("iam:policy", "iam", scope="global")
def iam_policies(ctx, _region):
    c = ctx.client("iam", ctx.home_region)
    for p in paginate(c, "list_policies", "Policies", Scope="Local"):
        tags = tag_list_to_dict(c.list_policy_tags(PolicyArn=p["Arn"]).get("Tags"))
        yield res("iam", "policy", "global", p["PolicyName"], p["Arn"], tags, name=p["PolicyName"])


# ---- Catch-all: Resource Groups Tagging API ---------------------------------
def parse_arn(arn):
    parts = arn.split(":", 5)
    service, region, resource = parts[2], parts[3], parts[5] if len(parts) > 5 else ""
    m = re.match(r"^([^:/]+)[:/](.+)$", resource)
    rtype, rid = (m.group(1), m.group(2)) if m else ((service if service != "s3" else "bucket"), resource)
    return service, rtype, region or "global", rid


@collector("tagging-api")
def tagging_api(ctx, region):
    c = ctx.client("resourcegroupstaggingapi", region)
    for m in paginate(c, "get_resources", "ResourceTagMappingList", ResourcesPerPage=100):
        arn = m["ResourceARN"]
        svc, rtype, reg, rid = parse_arn(arn)
        tags = tag_list_to_dict(m.get("Tags"))
        yield res(svc, rtype, reg, rid, arn, tags, name=tags.get("Name") or rid, source="tagging-api")


# --------------------------------------------------------------------------- #
# Custom resource types: a saved "aws <service> <operation> [--params]" command
# that is executed through boto3 (no AWS CLI install needed) in every scanned
# region, with each returned item turned into a resource.
#
# Spec (stored in custom_types.json):
#   name          "sagemaker:notebook-instance"  (service:type shown in the table)
#   command       "aws sagemaker list-notebook-instances"
#   scope         "regional" | "global"
#   items_path    where the list is in the response, e.g. "Reservations.Instances" (blank = auto)
#   id_field      item field holding the id   (blank = auto)
#   name_field    item field holding the name (blank = Name tag / auto)
#   arn_field     item field holding the ARN  (blank = auto)
#   arn_template  e.g. "arn:{partition}:es:{region}:{account}:domain/{DomainName}"
#                 used when the response has no ARN; {id} {name} {region} {account}
#                 {partition} and any top-level item field are available.
# Tags come from the item itself if it has Tags/TagList/TagSet, otherwise they are
# looked up by ARN with the Resource Groups Tagging API.
# --------------------------------------------------------------------------- #
CUSTOM_GROUP = "custom"
DEFAULT_TYPES_FILE = os.environ.get("AWS_TAG_AUDIT_TYPES") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "custom_types.json")
CUSTOM_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*(:[A-Za-z0-9_.\-]+)?$")

CLI_SERVICE_ALIASES = {"s3api": "s3", "configservice": "config"}
CLI_OPTS_WITH_VALUE = {"--region", "--profile", "--output", "--query", "--endpoint-url", "--max-items",
                       "--page-size", "--starting-token", "--color", "--ca-bundle", "--cli-read-timeout",
                       "--cli-connect-timeout", "--cli-binary-format"}
CLI_FLAGS = {"--no-paginate", "--debug", "--no-verify-ssl", "--no-sign-request", "--no-cli-pager", "--paginate"}
RESPONSE_META_KEYS = {"ResponseMetadata", "NextToken", "nextToken", "Marker", "NextMarker", "IsTruncated",
                      "MaxResults", "maxResults", "MaxItems", "Count", "ScannedCount", "NextContinuationToken"}
TAG_FIELDS = ("Tags", "TagList", "TagSet", "tags", "tagList", "TagsList")

EXAMPLE_TYPES = [
    {"name": "ec2:instance-running", "command": "aws ec2 describe-instances --filters Name=instance-state-name,Values=running",
     "scope": "regional", "items_path": "Reservations.Instances", "id_field": "InstanceId",
     "arn_template": "arn:{partition}:ec2:{region}:{account}:instance/{InstanceId}"},
    {"name": "opensearch:domain", "command": "aws opensearch list-domain-names", "scope": "regional",
     "items_path": "DomainNames", "id_field": "DomainName",
     "arn_template": "arn:{partition}:es:{region}:{account}:domain/{DomainName}"},
    {"name": "elasticache:cluster", "command": "aws elasticache describe-cache-clusters", "scope": "regional",
     "items_path": "CacheClusters", "id_field": "CacheClusterId", "arn_field": "ARN"},
    {"name": "sagemaker:notebook-instance", "command": "aws sagemaker list-notebook-instances", "scope": "regional",
     "items_path": "NotebookInstances", "id_field": "NotebookInstanceName", "arn_field": "NotebookInstanceArn"},
    {"name": "dynamodb:table-list", "command": "aws dynamodb list-tables", "scope": "regional",
     "arn_template": "arn:{partition}:dynamodb:{region}:{account}:table/{id}"},
]

_BOTOCORE = None


def _service_model(service):
    global _BOTOCORE
    if _BOTOCORE is None:
        _BOTOCORE = botocore.session.get_session()
    try:
        return _BOTOCORE.get_service_model(service)
    except Exception:
        known = _BOTOCORE.get_available_services()
        close = difflib.get_close_matches(service, known, 5)
        raise ValueError("Unknown AWS service '%s' for this boto3/botocore version.%s Upgrading boto3 adds newly released services."
                         % (service, (" Did you mean: " + ", ".join(close) + "?") if close else ""))


def _coerce_scalar(shape, v):
    t = shape.type_name
    if t in ("structure", "list", "map") and v.lstrip()[:1] in ("{", "["):
        return json.loads(v)
    if t in ("integer", "long"):
        return int(v)
    if t in ("float", "double"):
        return float(v)
    if t == "boolean":
        return v.lower() in ("true", "1", "yes")
    if t == "structure":
        return _shorthand(shape, v)
    if t == "list":
        return [_coerce_scalar(shape.member, x) for x in v.split(",")]
    return v


def _shorthand(shape, s):
    """CLI shorthand like  Name=instance-state-name,Values=running,stopped"""
    raw, cur = {}, None
    for part in s.split(","):
        if "=" in part:
            cur, val = part.split("=", 1)
            raw[cur] = [val]
        elif cur:
            raw[cur].append(part)
        else:
            raise ValueError("Can't parse %r; use Key=value,Key2=a,b or JSON" % s)
    out = {}
    for k, vals in raw.items():
        ms = shape.members.get(k)
        if ms is None:
            raise ValueError("'%s' isn't a field of %s (valid: %s)" % (k, shape.name, ", ".join(shape.members)))
        out[k] = [_coerce_scalar(ms.member, x) for x in vals] if ms.type_name == "list" else _coerce_scalar(ms, ",".join(vals))
    return out


def parse_cli_command(cmd):
    """'aws ec2 describe-instances --filters Name=x,Values=y' -> (service, Operation, params, warnings).
    Works offline (botocore's bundled API models), so it can validate before you connect."""
    cmd = re.sub(r"[\\`^]\s*\n", " ", cmd or "").strip()
    try:
        toks = shlex.split(cmd, posix=True)
    except ValueError as e:
        raise ValueError("Can't parse command: %s" % e)
    if toks and os.path.basename(toks[0]).lower() in ("aws", "aws.exe", "aws.cmd"):
        toks = toks[1:]
    warnings, clean, i = [], [], 0
    while i < len(toks):
        t = toks[i]
        base = t.split("=", 1)[0]
        if base in CLI_OPTS_WITH_VALUE:
            warnings.append("ignored %s (the scanner sets region/profile/paging itself)" % base)
            i += 1 if "=" in t else 2
            continue
        if t in CLI_FLAGS:
            warnings.append("ignored %s" % t)
            i += 1
            continue
        clean.append(t)
        i += 1
    if len(clean) < 2:
        raise ValueError("Expected:  aws <service> <operation> [--param value ...]   e.g.  aws ec2 describe-volumes")
    svc_cli, op_cli, rest = clean[0], clean[1], clean[2:]
    if svc_cli == "s3" and op_cli in ("ls", "cp", "sync", "mb", "rb", "mv", "rm"):
        raise ValueError("'aws s3 %s' is a CLI-only shortcut; use the API form, e.g. 'aws s3api list-buckets'" % op_cli)
    service = CLI_SERVICE_ALIASES.get(svc_cli, svc_cli)
    model = _service_model(service)
    ops = {xform_name(n, "-"): n for n in model.operation_names}
    if op_cli not in ops:
        listy = [o for o in ops if o.startswith(("list-", "describe-", "get-"))]
        close = difflib.get_close_matches(op_cli, list(ops), 5) or sorted(listy)[:12]
        raise ValueError("'%s' isn't an operation of %s. Try: %s" % (op_cli, svc_cli, ", ".join(close)))
    op = ops[op_cli]
    shape = model.operation_model(op).input_shape
    members = shape.members if shape else {}
    by_cli = {xform_name(m, "-"): m for m in members}
    params, i = {}, 0
    while i < len(rest):
        t = rest[i]
        if not t.startswith("--"):
            raise ValueError("Unexpected argument %r (parameters look like --name value)" % t)
        flag, eq, inline = t[2:].partition("=")
        neg = False
        if flag not in by_cli and flag.startswith("no-") and flag[3:] in by_cli:
            flag, neg = flag[3:], True
        if flag not in by_cli:
            raise ValueError("--%s isn't a parameter of %s %s. Valid: %s" % (
                flag, svc_cli, op_cli, ", ".join("--" + k for k in sorted(by_cli)) or "(none)"))
        m = members[by_cli[flag]]
        vals, j = ([inline] if eq else []), i + 1
        if not eq:
            while j < len(rest) and not rest[j].startswith("--"):
                vals.append(rest[j])
                j += 1
        i = j
        if m.type_name == "boolean":
            params[by_cli[flag]] = (vals[0].lower() in ("true", "1", "yes")) if vals else not neg
        elif not vals:
            raise ValueError("--%s needs a value" % flag)
        elif m.type_name == "list" and not (len(vals) == 1 and vals[0].lstrip().startswith("[")):
            params[by_cli[flag]] = [_coerce_scalar(m.member, v) for v in vals]
        elif len(vals) == 1:
            params[by_cli[flag]] = _coerce_scalar(m, vals[0])
        else:
            raise ValueError("--%s takes one value, got %d" % (flag, len(vals)))
    return service, op, params, warnings


READ_ONLY_PREFIXES = ("List", "Describe", "Get", "Search", "Lookup", "BatchGet")


def check_read_only(op):
    if not op.startswith(READ_ONLY_PREFIXES):
        raise ValueError("Only read-only operations are allowed for resource types (List*, Describe*, Get*, Search*, "
                         "Lookup*, BatchGet*); '%s' could change things. It would run in every scanned region." % xform_name(op, "-"))


def run_cli_command(ctx, command, region):
    """Execute a parsed command via boto3 and return all response pages."""
    service, op, params, _ = parse_cli_command(command)
    check_read_only(op)
    c = ctx.client(service, region)
    method = xform_name(op)
    if c.can_paginate(method):
        return list(c.get_paginator(method).paginate(**params))
    return [getattr(c, method)(**params)]


def detect_items_path(page):
    for k, v in page.items():
        if k not in RESPONSE_META_KEYS and isinstance(v, list):
            return k
    return ""


def extract_items(page, path):
    cur = [page]
    for seg in [s for s in (path or "").replace("[]", "").split(".") if s]:
        nxt = []
        for o in cur:
            v = o.get(seg) if isinstance(o, dict) else None
            if isinstance(v, list):
                nxt.extend(v)
            elif v is not None:
                nxt.append(v)
        cur = nxt
    return cur


def _item_tags(item):
    for k in TAG_FIELDS:
        if isinstance(item, dict) and k in item:
            v = item[k]
            if isinstance(v, dict):
                return {str(a): str(b) for a, b in v.items()}
            if isinstance(v, list):
                out = {}
                for t in v:
                    if isinstance(t, dict):
                        kk = t.get("Key", t.get("key", t.get("TagKey")))
                        if kk is not None:
                            out[kk] = t.get("Value", t.get("value", t.get("TagValue", "")))
                return out
    return None


def _op_nouns(op):
    """DescribeCacheClusters -> ['CacheCluster', 'Cluster']; ListDomainNames -> ['DomainName', 'Domain', ...]"""
    base = re.sub(r"^(List|Describe|Get|Search|Lookup|BatchGet)", "", op or "")
    forms = [base]
    if base.endswith("ies"):
        forms.append(base[:-3] + "y")
    if base.endswith("es"):
        forms.append(base[:-2])
    if base.endswith("s"):
        forms.append(base[:-1])
    out = []
    for f in forms:
        words = re.findall(r"[A-Z][a-z0-9]*|[a-z0-9]+", f)
        for i in range(len(words)):
            n = "".join(words[i:])
            if n and n not in out:
                out.append(n)
    return out


def _guess_by_noun(item, op, suffixes, want_arn=False):
    for noun in _op_nouns(op):
        for suf in suffixes:
            k = noun + suf
            v = item.get(k)
            if isinstance(v, (str, int)) and not isinstance(v, bool) and (not want_arn or str(v).startswith("arn:")):
                return k
    return ""


def _guess_field(item, suffixes, want_arn=False):
    for suf in suffixes:
        for k, v in item.items():
            if isinstance(v, (str, int)) and not isinstance(v, bool) and k.endswith(suf):
                if want_arn and not str(v).startswith("arn:"):
                    continue
                return k
    return ""


class _Fmt(dict):
    def __missing__(self, k):
        raise KeyError(k)


def build_custom(ctx, spec, region, pages):
    """Turn response pages into resources. Returns (resources, info)."""
    name = spec["name"]
    svc, _, rtype = name.partition(":")
    service_for_row = svc
    if not rtype:
        service_for_row, rtype = parse_cli_command(spec["command"])[0], name
    path = spec.get("items_path") or (detect_items_path(pages[0]) if pages else "")
    items = [it for p in pages for it in extract_items(p, path)]
    first = next((it for it in items if isinstance(it, dict)), None)
    op = parse_cli_command(spec["command"])[1]
    id_f = spec.get("id_field") or (
        (_guess_by_noun(first, op, ("Id", "ID", "Identifier", "Name", "")) or
         next((k for k in ("Id", "id", "Name", "name") if k in first), "") or
         _guess_field(first, ("Id", "ID", "Identifier", "Name", "Arn", "ARN"))) if first else "")
    arn_f = spec.get("arn_field") or ("" if spec.get("arn_template") else (
        (_guess_by_noun(first, op, ("Arn", "ARN"), True) or _guess_field(first, ("Arn", "ARN", "arn"), True)) if first else ""))
    # Name: explicit field, else a literal Name/name field; otherwise the Name tag (handled in res()).
    name_f = spec.get("name_field") or (next((k for k in ("Name", "name") if k in first and isinstance(first[k], str)), "") if first else "")
    tmpl = spec.get("arn_template") or ""
    info = {"items_path": path, "id_field": id_f, "arn_field": arn_f, "name_field": name_f,
            "count": len(items), "first_item": first if first is not None else (items[0] if items else None),
            "problems": []}
    out, need_lookup = [], []
    for it in items:
        if isinstance(it, dict):
            scal = {k: v for k, v in it.items() if isinstance(v, (str, int, float)) and not isinstance(v, bool)}
            rid = str(it.get(id_f, "")) if id_f else ""
            tags = _item_tags(it)
            nm = str(it.get(name_f, "")) if name_f else ""
            arn = str(it.get(arn_f, "")) if arn_f else ""
        else:
            s = str(it)
            scal, tags, nm = {}, None, ""
            arn = s if s.startswith("arn:") else ""
            rid = s.rsplit("/", 1)[-1] if arn else s
        if not arn and tmpl:
            try:
                arn = tmpl.format_map(_Fmt(scal, partition=ctx.partition, region=region, account=ctx.account, id=rid, name=nm or rid))
            except KeyError as e:
                info["problems"].append("ARN template uses {%s}, which this item doesn't have" % e.args[0])
        if (not rid or (id_f and id_f == arn_f)) and arn:
            rid = arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
        r = res(service_for_row, rtype, "global" if spec.get("scope") == "global" else region, rid,
                arn or "custom://%s/%s/%s" % (name, region, rid), tags or {}, name=nm or None, source="custom")
        if tags is None and arn.startswith("arn:"):
            need_lookup.append(r)
        out.append(r)
    if need_lookup:
        tregion = ctx.home_region if spec.get("scope") == "global" else region
        c = ctx.client("resourcegroupstaggingapi", tregion)
        for chunk in chunks(need_lookup, 100):
            try:
                resp = c.get_resources(ResourceARNList=[r["arn"] for r in chunk])
                found = {m["ResourceARN"]: tag_list_to_dict(m.get("Tags")) for m in resp.get("ResourceTagMappingList", [])}
                for r in chunk:
                    r["tags"] = found.get(r["arn"], {})
            except (ClientError, BotoCoreError) as e:
                info["problems"].append("tag lookup failed: %s" % err_code(e))
                break
    for r in out:
        if not r["name"]:
            r["name"] = r["tags"].get("Name") or r["id"]
    info["tags_source"] =("inline (%s)" % next((k for k in TAG_FIELDS if first and k in first), "")) if first and _item_tags(first) is not None \
        else ("looked up via Tagging API" if need_lookup else "none found")
    if items and not any(r["arn"].startswith("arn:") for r in out):
        info["problems"].append("No ARN: set 'ARN field' or 'ARN template', otherwise these can be listed but not tagged")
    info["problems"] = sorted(set(info["problems"]))
    return out, info


def _custom_collector(spec):
    def fn(ctx, region):
        pages = run_cli_command(ctx, spec["command"], region)
        for r in build_custom(ctx, spec, region, pages)[0]:
            yield r
    return fn


def validate_custom_spec(spec, existing_names=()):
    n = (spec.get("name") or "").strip()
    if not CUSTOM_NAME_RE.match(n):
        raise ValueError("Name must look like 'service:type' (letters, digits, - _ .), e.g. sagemaker:notebook")
    builtin = {c[0] for c in COLLECTORS if c[1] != CUSTOM_GROUP} | {c[1] for c in COLLECTORS if c[1] != CUSTOM_GROUP}
    if n in builtin:
        raise ValueError("'%s' is already a built-in type; pick another name" % n)
    if n in existing_names:
        raise ValueError("A custom type named '%s' already exists" % n)
    if spec.get("scope", "regional") not in ("regional", "global"):
        raise ValueError("scope must be regional or global")
    check_read_only(parse_cli_command(spec.get("command", ""))[1])
    return True


def load_custom_types(path=None):
    path = path or DEFAULT_TYPES_FILE
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("types", []) if isinstance(data, dict) else data


def save_custom_types(specs, path=None):
    path = path or DEFAULT_TYPES_FILE
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"version": 1, "types": specs}, f, indent=2)
    os.replace(tmp, path)
    return path


def register_custom_types(specs):
    COLLECTORS[:] = [c for c in COLLECTORS if c[1] != CUSTOM_GROUP]
    for s in specs:
        COLLECTORS.append((s["name"], CUSTOM_GROUP, s.get("scope", "regional"), _custom_collector(s)))


# --------------------------------------------------------------------------- #
# Scan
# --------------------------------------------------------------------------- #
def evaluate(tags, key):
    """Return None if the tag is present and non-empty, else a reason string."""
    if key in tags:
        return None if str(tags[key]).strip() else "empty-value"
    near = [k for k in tags if k.strip().lower() == key.lower()]
    return ("wrong-case-key: " + ", ".join(near)) if near else "missing"


def run_scan(ctx, regions, include, exclude, use_tagging_api, progress=None):
    say = progress or (lambda m: print(m, file=sys.stderr))
    ctx.scan_errors = []
    ctx.skipped_arns = set()  # resources built-in collectors deliberately skip; catch-all must not re-add them
    ctx.region_filter = set(regions) if regions else None
    tasks = []
    for name, group, scope, fn in COLLECTORS:
        if name == "tagging-api" and not use_tagging_api:
            continue
        if include and group not in include and name not in include and name != "tagging-api":
            continue
        if exclude and (group in exclude or name in exclude):
            continue
        if scope == "global":
            tasks.append((name, "global", fn, ctx.home_region))
        else:
            tasks.extend((name, r, fn, r) for r in regions)

    ctx.tasks_per_region = Counter(t[1] for t in tasks)
    results, done = [], 0
    lock = threading.Lock()

    def run(name, label, fn, region):
        out = []
        try:
            for r in fn(ctx, region):
                out.append(r)
        except (ClientError, BotoCoreError) as e:
            code = err_code(e)
            if isinstance(e, EndpointConnectionError):
                code = "ServiceNotInRegion"
            with lock:
                ctx.scan_errors.append((name, label, code, str(e)[:300]))
        return out

    say("Scanning %d collector/region combos with %d workers..." % (len(tasks), ctx.workers))
    with ThreadPoolExecutor(max_workers=ctx.workers) as pool:
        futs = {pool.submit(run, *t): t for t in tasks}
        for f in as_completed(futs):
            results.extend(f.result())
            done += 1
            if done % 25 == 0 or done == len(tasks):
                say("  %d/%d done, %d resources so far" % (done, len(tasks), len(results)))

    # Merge by ARN. Priority: built-in enumeration > your custom types > Tagging API catch-all.
    priority = {"enum": 0, "custom": 1}
    merged = {}
    for r in sorted(results, key=lambda x: priority.get(x["source"], 2)):
        if r["source"] == "tagging-api" and r["arn"] in ctx.skipped_arns:
            continue
        merged.setdefault(r["arn"], r)
    return sorted(merged.values(), key=lambda r: (r["service"], r["type"], r["region"], r["name"], r["id"]))


DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError",
                "UnrecognizedClientException", "InvalidClientTokenId", "OptInRequired"}


def summarize_errors(ctx):
    """Split scan errors into (blocked_regions, other_errors). A region counts as blocked when
    ~all of its collectors were denied - typically an SCP region restriction or a region not opted in."""
    denied = Counter(e[1] for e in ctx.scan_errors if e[2] in DENIED_CODES)
    total = getattr(ctx, "tasks_per_region", {})
    blocked = sorted(r for r, n in denied.items() if r != "global" and total.get(r) and n >= 0.8 * total[r])
    others = [e for e in ctx.scan_errors if e[2] != "ServiceNotInRegion" and e[1] not in blocked]
    return blocked, others


def write_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:  # -sig so Excel reads UTF-8 correctly
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def cmd_scan(args):
    ctx = Ctx(args.profile, args.region, args.workers)
    regions = args.regions or ctx.enabled_regions()
    include = set(args.services or [])
    exclude = set(args.exclude_services or [])
    print("Account %s  partition %s  caller %s" % (ctx.account, ctx.partition, ctx.caller_arn), file=sys.stderr)
    print("Regions: %s" % ", ".join(regions), file=sys.stderr)

    t0 = time.time()
    resources = run_scan(ctx, regions, include, exclude, not args.no_tagging_api)
    key = args.key

    untagged = []
    for r in resources:
        reason = evaluate(r["tags"], key)
        r["tags_json"] = json.dumps(r["tags"], sort_keys=True)
        r["has_" + key] = "no" if reason else "yes"
        if reason:
            row = dict(r)
            row[key] = ""
            row["reason"] = reason
            untagged.append(row)

    os.makedirs(args.out, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = os.path.join(args.out, "%s_%s" % (ctx.account, stamp))
    untagged_path = base + "_untagged.csv"
    inv_path = base + "_inventory.csv"
    err_path = base + "_scan_errors.csv"

    # Tag-value column FIRST so it's easy to fill in Excel.
    write_csv(untagged_path, untagged, [key, "reason", "service", "type", "region", "name", "id", "arn", "source", "tags_json"])
    write_csv(inv_path, resources, ["has_" + key, "service", "type", "region", "name", "id", "arn", "source", "tags_json"])
    with open(err_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["collector", "region", "error_code", "message"])
        w.writerows(sorted(ctx.scan_errors))

    # Summary
    print("\nScan finished in %.0fs: %d resources, %d missing tag '%s'." % (time.time() - t0, len(resources), len(untagged), key))
    if untagged:
        by_type = Counter("%s:%s" % (r["service"], r["type"]) for r in untagged)
        print("\nMissing '%s' by resource type:" % key)
        for t, n in by_type.most_common():
            print("  %6d  %s" % (n, t))
        by_region = Counter(r["region"] for r in untagged)
        print("\nMissing '%s' by region:" % key)
        for t, n in by_region.most_common():
            print("  %6d  %s" % (n, t))
    blocked, real_errors = summarize_errors(ctx)
    if blocked:
        print("\nRegions where almost every call was denied (SCP region restriction or not opted in), "
              "nothing could be scanned there:\n  " + ", ".join(blocked))
    if real_errors:
        print("\n%d collector errors (often AccessDenied) - see %s" % (len(real_errors), err_path))
        for code, n in Counter(e[2] for e in real_errors).most_common(5):
            print("  %6d  %s" % (n, code))
    print("\nUntagged list : %s" % untagged_path)
    print("Full inventory: %s" % inv_path)
    print("\nNext: fill the '%s' column in the untagged CSV, then run:\n  python %s apply --csv \"%s\"" % (key, os.path.basename(sys.argv[0]), untagged_path))
    print("  (or add --interactive to be prompted for each resource)")


# --------------------------------------------------------------------------- #
# Apply
# --------------------------------------------------------------------------- #
class Unsupported(Exception):
    pass


def native_tag(ctx, row, key, val):
    """Service-specific tagging, used when the Tagging API can't (or won't)."""
    svc, rtype, region, rid, arn = row["service"], row["type"], row["region"], row["id"], row["arn"]
    if region in ("", "global"):
        region = ctx.home_region
    if svc == "ec2":
        ctx.client("ec2", region).create_tags(Resources=[rid], Tags=[{"Key": key, "Value": val}])
    elif svc == "iam":
        c = ctx.client("iam", ctx.home_region)
        name = rid.rsplit("/", 1)[-1]
        t = [{"Key": key, "Value": val}]
        if rtype == "role":
            c.tag_role(RoleName=name, Tags=t)
        elif rtype == "user":
            c.tag_user(UserName=name, Tags=t)
        elif rtype == "policy":
            c.tag_policy(PolicyArn=arn, Tags=t)
        elif rtype == "instance-profile":
            c.tag_instance_profile(InstanceProfileName=name, Tags=t)
        else:
            raise Unsupported("iam type %s" % rtype)
    elif svc == "route53" and rtype == "hostedzone":
        ctx.client("route53", ctx.home_region).change_tags_for_resource(
            ResourceType="hostedzone", ResourceId=rid.split("/")[-1], AddTags=[{"Key": key, "Value": val}])
    elif svc == "s3":
        c = ctx.client("s3", region)
        try:
            existing = c.get_bucket_tagging(Bucket=rid).get("TagSet", [])
        except ClientError as e:
            if err_code(e) != "NoSuchTagSet":
                raise
            existing = []
        merged = [t for t in existing if t["Key"] != key] + [{"Key": key, "Value": val}]
        c.put_bucket_tagging(Bucket=rid, Tagging={"TagSet": merged})  # put REPLACES, hence the merge
    elif svc == "logs":
        ctx.client("logs", region).tag_log_group(logGroupName=rid, tags={key: val})
    elif svc == "lambda":
        ctx.client("lambda", region).tag_resource(Resource=arn, Tags={key: val})
    elif svc == "sqs":
        url = ctx.client("sqs", region).get_queue_url(QueueName=rid)["QueueUrl"]
        ctx.client("sqs", region).tag_queue(QueueUrl=url, Tags={key: val})
    else:
        raise Unsupported("no native tagger for %s:%s" % (svc, rtype))


RETRYABLE_TAG_CODES = ("Throttl", "LimitExceeded", "ConcurrentModification", "ResourceInUse", "TooManyRequests",
                       "RequestLimitExceeded", "InternalServiceException", "ServiceUnavailable")


def is_retryable_tag_error(f):
    blob = "%s %s" % (f.get("ErrorCode", ""), f.get("ErrorMessage", ""))
    return any(c in blob for c in RETRYABLE_TAG_CODES) or "being updated" in blob


def apply_tags(ctx, plan, key, dry_run, log=print):
    """plan: list of (row, value). Returns list of result rows."""
    results = []
    by_region_value = defaultdict(list)
    native_first = []
    no_arn = []
    for row, val in plan:
        if not row["arn"].startswith("arn:"):
            no_arn.append((row, val))
        elif row["service"] in ("iam", "route53"):
            native_first.append((row, val))
        else:
            region = ctx.home_region if row["region"] in ("", "global") else row["region"]
            by_region_value[(region, val)].append(row)

    def record(row, val, status, msg=""):
        out = dict(row)
        out[key] = val
        out["status"] = status
        out["message"] = msg
        results.append(out)
        mark = {"tagged": "OK  ", "dry-run": "DRY ", "failed": "FAIL"}.get(status, status)
        log("  %s %s=%-12s %-28s %-14s %s %s" % (mark, key, val, row["service"] + ":" + row["type"], row["region"], row["name"] or row["id"], ("- " + msg) if msg and status == "failed" else ""))

    def try_native(row, val, prior_msg=""):
        try:
            native_tag(ctx, row, key, val)
            record(row, val, "tagged", "native API")
        except Unsupported as e:
            record(row, val, "failed", (prior_msg + " | " if prior_msg else "") + str(e))
        except (ClientError, BotoCoreError) as e:
            record(row, val, "failed", (prior_msg + " | " if prior_msg else "") + "%s: %s" % (err_code(e), str(e)[:200]))

    if dry_run:
        for row, val in plan:
            record(row, val, "dry-run", "would set %s=%s" % (key, val))
        return results

    for row, val in no_arn:
        record(row, val, "failed", "no ARN for this resource (custom type needs an ARN field or ARN template)")

    def tag_batch(c, arns, val):
        try:
            failed = c.tag_resources(ResourceARNList=arns, Tags={key: val}).get("FailedResourcesMap", {}) or {}
            # Some services (e.g. DynamoDB) allow one tag update per resource at a time and report
            # that inside FailedResourcesMap, where boto3's own retries never see it. Back off and retry.
            for delay in (2, 4, 8, 16):
                retry = [a for a, f in failed.items() if is_retryable_tag_error(f)]
                if not retry:
                    break
                time.sleep(delay)
                again = c.tag_resources(ResourceARNList=retry, Tags={key: val}).get("FailedResourcesMap", {}) or {}
                failed = {a: f for a, f in failed.items() if a not in retry}
                failed.update(again)
            return failed
        except (ClientError, BotoCoreError) as e:
            if len(arns) > 1:  # one bad ARN can fail the whole call; retry one by one
                out = {}
                for a in arns:
                    out.update(tag_batch(c, [a], val))
                return out
            return {a: {"ErrorCode": err_code(e), "ErrorMessage": str(e)[:200]} for a in arns}

    for (region, val), rows in sorted(by_region_value.items()):
        c = ctx.client("resourcegroupstaggingapi", region)
        for chunk in chunks(rows, 20):  # TagResources max 20 ARNs per call
            arns = [r["arn"] for r in chunk]
            failed = tag_batch(c, arns, val)
            for r in chunk:
                if r["arn"] in failed:
                    f = failed[r["arn"]]
                    try_native(r, val, "tagging-api: %s %s" % (f.get("ErrorCode", ""), f.get("ErrorMessage", "")))
                else:
                    record(r, val, "tagged", "tagging-api")
    for row, val in native_first:
        try_native(row, val)
    return results


def read_rows(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def valid_value(v):
    return len(v) <= 256 and bool(TAG_VALUE_RE.match(v))


def describe_row(row):
    try:
        tags = json.loads(row.get("tags_json") or "{}")
    except ValueError:
        tags = {}
    tag_s = ", ".join("%s=%s" % kv for kv in sorted(tags.items())) or "(no tags)"
    return "%s:%s  %s  %s  (%s)\n      tags: %s" % (row["service"], row["type"], row["region"], row["name"] or "-", row["id"], tag_s[:300])


def interactive_collect(rows, key):
    """Prompt for a value per resource. Returns {index: value}."""
    answers = {}
    last = None
    todo = [i for i, r in enumerate(rows) if not (r.get(key) or "").strip()]
    print("\n%d resources need a '%s' value. For each one type the value and press Enter." % (len(todo), key))
    print("  Enter = skip   .  = same as previous   .all = previous value for ALL remaining of this service:type   q = stop asking\n")
    n = 0
    while n < len(todo):
        i = todo[n]
        row = rows[i]
        print("[%d/%d] %s" % (n + 1, len(todo), describe_row(row)))
        hint = " [. = %s]" % last if last else ""
        try:
            v = input("    %s value%s: " % (key, hint)).strip()
        except EOFError:
            v = "q"
        if v.lower() == "q":
            break
        if v == "":
            n += 1
            continue
        if v in (".", ".all"):
            if not last:
                print("    no previous value yet")
                continue
            if v == ".all":
                kind = (row["service"], row["type"])
                for j in todo[n:]:
                    if (rows[j]["service"], rows[j]["type"]) == kind:
                        answers[j] = last
                print("    -> %s applied to every remaining %s:%s" % (last, *kind))
                todo = [j for j in todo[:n]] + [j for j in todo[n:] if j not in answers]
                continue
            v = last
        if not valid_value(v):
            print("    invalid: max 256 chars; letters, numbers, spaces and _ . : / = + - @ only")
            continue
        answers[i] = v
        last = v
        n += 1
    return answers


def cmd_apply(args):
    key = args.key
    rows = read_rows(args.csv)
    if not rows:
        sys.exit("CSV is empty.")
    if key not in rows[0]:
        sys.exit("CSV has no '%s' column. Was it produced by 'scan' with the same --key?" % key)

    # Optional filters
    def keep(r):
        if args.services and r["service"] not in args.services and "%s:%s" % (r["service"], r["type"]) not in args.services:
            return False
        if args.regions and r["region"] not in args.regions:
            return False
        return True
    rows = [r for r in rows if keep(r)]

    if args.value is not None:
        if not valid_value(args.value):
            sys.exit("Invalid --value. Max 256 chars; letters, numbers, spaces and _ . : / = + - @ only.")
        for r in rows:
            if not (r.get(key) or "").strip() or args.overwrite_csv_values:
                r[key] = args.value

    if args.interactive:
        answers = interactive_collect(rows, key)
        for i, v in answers.items():
            rows[i][key] = v
        stem = os.path.splitext(args.csv)[0]
        ans_path = stem + "_answers.csv"
        write_csv(ans_path, rows, list(rows[0].keys()))
        print("\nYour answers were saved to %s (re-run apply on that file to resume)." % ans_path)

    plan, bad = [], []
    for r in rows:
        v = (r.get(key) or "").strip()
        if not v:
            continue
        (plan if valid_value(v) else bad).append((r, v))
    for r, v in bad:
        print("SKIP invalid value %r for %s" % (v, r["arn"]))
    if not plan:
        print("Nothing to do: no rows have a '%s' value." % key)
        return

    print("\nPlan: set tag '%s' on %d resources (%d rows left blank are skipped)." % (key, len(plan), len(rows) - len(plan) - len(bad)))
    for v, n in Counter(v for _, v in plan).most_common():
        print("  %6d  %s=%s" % (n, key, v))
    if not args.dry_run and not args.yes:
        if input("\nApply these tags now? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted, nothing changed.")
            return

    ctx = Ctx(args.profile, args.region, args.workers)
    print("Account %s  caller %s\n" % (ctx.account, ctx.caller_arn))
    # Guard against applying a CSV from another account.
    accts = {r["arn"].split(":")[4] for r, _ in plan if r["arn"].split(":")[4]}
    if accts and accts != {ctx.account}:
        sys.exit("CSV contains resources from account(s) %s but you're logged into %s. Refusing." % (", ".join(sorted(accts)), ctx.account))

    results = apply_tags(ctx, plan, key, args.dry_run)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = os.path.splitext(args.csv)[0] + "_results_%s.csv" % stamp
    fields = ["status", "message", key] + [f for f in results[0].keys() if f not in ("status", "message", key)]
    write_csv(out, results, fields)
    c = Counter(r["status"] for r in results)
    print("\nDone: %s" % ", ".join("%s=%d" % kv for kv in c.items()))
    print("Results: %s" % out)
    if c.get("failed"):
        print("Failed rows can be fixed and re-applied straight from the results CSV:\n  python %s apply --csv \"%s\" --services <svc>" % (os.path.basename(sys.argv[0]), out))


# --------------------------------------------------------------------------- #
def cmd_types(args):
    if args.test:
        spec = next((s for s in load_custom_types(args.types_file) if s["name"] == args.test), None)
        if not spec:
            sys.exit("No custom type named %r in %s" % (args.test, args.types_file))
        ctx = Ctx(args.profile, args.region, args.workers)
        region = ctx.home_region if spec.get("scope") == "global" else ctx.start_region
        rows, info = build_custom(ctx, spec, region, run_cli_command(ctx, spec["command"], region))
        print("%s in %s: %d items  (items_path=%r id=%r arn=%r name=%r, tags %s)" % (
            spec["name"], region, info["count"], info["items_path"], info["id_field"], info["arn_field"],
            info["name_field"], info["tags_source"]))
        for prob in info["problems"]:
            print("  WARNING:", prob)
        for r in rows[:25]:
            print("  %-30s %-30s %s  %s" % (r["id"][:30], r["name"][:30], r["arn"], json.dumps(r["tags"])[:80]))
        return
    print("Built-in types (use with --services; a service name selects all its types):")
    groups = defaultdict(list)
    for name, group, scope, _ in COLLECTORS:
        if group != CUSTOM_GROUP:
            groups[group].append(name + (" (global)" if scope == "global" else ""))
    for g in sorted(groups):
        print("  %-16s %s" % (g, ", ".join(groups[g])))
    customs = load_custom_types(args.types_file)
    print("\nCustom types from %s:" % args.types_file)
    for s in customs:
        print("  %-30s %-8s %s" % (s["name"], s.get("scope", "regional"), s["command"]))
    if not customs:
        print("  (none yet - add them in the GUI, or edit the JSON; see README)")


def _safe_console():
    # Windows consoles default to cp1252; never crash on a resource name it can't print.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv=None):
    _safe_console()
    p = argparse.ArgumentParser(description="Find AWS resources missing a tag and tag them.")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--profile", help="AWS CLI profile to use")
    common.add_argument("--region", help="Starting region for API calls (default: profile/env region)")
    common.add_argument("--key", default="Program", help="Tag key to check/set (default: Program, case-sensitive)")
    common.add_argument("--regions", nargs="+", help="Limit to these regions (default: all enabled)")
    common.add_argument("--services", nargs="+", help="Limit to these services, e.g. ec2 s3 rds iam ec2:volume")
    common.add_argument("--workers", type=int, default=8, help="Parallel API workers (default 8)")
    common.add_argument("--types-file", default=DEFAULT_TYPES_FILE, help="Custom resource types JSON (default: custom_types.json next to this script)")
    sub = p.add_subparsers(dest="cmd", required=True)

    ty = sub.add_parser("types", parents=[common], help="List built-in + custom resource types; optionally test a custom one")
    ty.add_argument("--test", metavar="NAME", help="Run this custom type in --region and print what it finds")
    ty.set_defaults(func=cmd_types)

    s = sub.add_parser("scan", parents=[common], help="Inventory resources and list those missing the tag")
    s.add_argument("--exclude-services", nargs="+", help="Skip these collectors, e.g. logs ec2:network-interface")
    s.add_argument("--no-tagging-api", action="store_true", help="Don't use the Resource Groups Tagging API catch-all")
    s.add_argument("--out", default="tag-audit-output", help="Output directory (default ./tag-audit-output)")
    s.set_defaults(func=cmd_scan)

    a = sub.add_parser("apply", parents=[common], help="Add the tag using values from the CSV / prompts")
    a.add_argument("--csv", required=True, help="Untagged CSV produced by 'scan' (or a results/answers CSV)")
    a.add_argument("--interactive", "-i", action="store_true", help="Prompt for a value for each row that has none")
    a.add_argument("--value", help="Use this value for every row that has none in the CSV")
    a.add_argument("--overwrite-csv-values", action="store_true", help="With --value, also replace values already in the CSV")
    a.add_argument("--dry-run", action="store_true", help="Show what would be tagged, change nothing")
    a.add_argument("--yes", "-y", action="store_true", help="Don't ask for confirmation")
    a.set_defaults(func=cmd_apply)

    args = p.parse_args(argv)
    try:
        register_custom_types(load_custom_types(args.types_file))
    except (ValueError, OSError) as e:
        sys.exit("Can't load custom types from %s: %s" % (args.types_file, e))
    try:
        args.func(args)
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")


if __name__ == "__main__":
    main()
