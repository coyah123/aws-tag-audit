# aws-tag-audit

Finds every AWS resource that is missing the `Program` tag, writes them to a CSV, and then adds the tag with a value you choose for each resource.

There are two ways to run it:

- **`aws_tag_audit_gui.py`**: a desktop GUI. You pick regions from a checklist, choose which tag keys are required, scan, select rows, set values and apply.
- **`aws_tag_audit.py`**: a CLI with `scan` and `apply` commands. Values come from a CSV you fill in, a prompt for each resource, or one value for all.

Both work on **Windows and macOS** (and Linux). They need Python 3.8+ and `boto3`, nothing else.

## Quick start

| | Open the GUI | Run the CLI |
|---|---|---|
| **Windows** | double-click `run.bat` | `run.bat scan --profile myprofile` |
| **macOS** | double-click `run.command`, or run `./run.sh` in Terminal | `./run.sh scan --profile myprofile` |
| **Linux** | `./run.sh` | `./run.sh scan --profile myprofile` |

On first run, the launcher:
- creates a private Python environment in `.venv`
- installs `boto3`, plus `botocore[crt]` if it can, so that `aws login` profiles work
- checks that Tkinter is available

After that it starts right away. With no arguments it opens the GUI. With arguments, they go to the CLI, so `run.bat apply --csv file.csv -i` works the same as `python aws_tag_audit.py apply --csv file.csv -i`.

**Python install notes**
- **Windows:** install Python from python.org and tick **"Add python.exe to PATH"**. The default install includes Tkinter.
- **macOS:**
  - The python.org installer includes Tkinter.
  - With Homebrew Python, also run `brew install python-tk`.
  - The first time you open `run.command`, right-click it and choose **Open** to get past Gatekeeper.
  - If `./run.sh` says permission denied, run `chmod +x run.sh run.command`.
- **Linux:** `sudo apt install python3 python3-venv python3-tk`.

**Manual install** (instead of the launchers): `pip install -r requirements.txt`, then run `python aws_tag_audit_gui.py` or `python aws_tag_audit.py …`.

**Offline install:** on a machine with internet, download the wheels for the *target* OS and Python version:
```
pip download boto3 "botocore[crt]" -d wheels
```
Copy the `wheels` folder over and install from it:
```
pip install --no-index --find-links wheels boto3
```
The launchers create the venv with `--system-site-packages`, so if boto3 is already installed system-wide, nothing is downloaded.

## Signing in

The tool uses the same credentials as the AWS CLI. You have three options:

1. **A profile.** Pick it in the GUI's Profile box, or pass `--profile` to the CLI. This works for profiles set up with `aws configure`, `aws configure sso` / `aws sso login`, and `aws login`.
   - `aws login` (browser sign-in) profiles need `botocore[crt]`. The launchers install it, and the tool tells you exactly what to install if it's missing.
2. **Environment variables** that are already set in your shell (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`). Use profile `(default)`.
3. **Paste credentials into the GUI: Credentials → Update credentials…** (or the **Credentials…** button next to Connect).
   - Paste the lines you'd run in a shell, for example the block from the AWS access portal's *Command line or programmatic access* page. All of these formats work: `export KEY=VALUE`, `set KEY=VALUE`, `$env:KEY="VALUE"` and `KEY=VALUE`.
   - **Apply & verify** loads them and reconnects. The status line shows the account, or the AWS error if the keys are wrong or expired.
   - When temporary credentials expire mid-session, paste fresh ones. You don't need to restart, and pending changes are not lost.
   - Pasted values stay **in memory only**: they are never written to disk, they are cleared from the text box after Apply, and secrets are masked in the log.
   - Pasting access keys switches the profile box to `(default)`, because a named profile would otherwise override them.
   - **Credentials → Clear pasted credentials** removes the pasted values again.

## GUI

```bash
python aws_tag_audit_gui.py        # or run.bat / ./run.sh
```

Keep `aws_tag_audit.py` in the same folder, because the GUI uses its scan and tagging code.

1. **Connect.** Pick an AWS CLI profile (or `(default)`) and a starting region, then click Connect. See [Signing in](#signing-in). The account, partition and caller are shown, and your account's enabled regions load into a checklist.
2. **Regions.** Tick the regions to scan. All / None buttons are provided.
3. **Required tag keys.** Add every key you require, for example `Program`, `Owner` and `CostCenter`. A resource is flagged if it is missing *any* of them, and each key gets its own column.
   - After a scan, the key box becomes a dropdown of every tag key used in your account, most common first. Picking one adds it.
   - Keys stamped automatically by AWS or Kubernetes (`aws:`, `eks:`, `kubernetes.io/…`) are not suggested.
   - You can add or remove keys **after** a scan and the table updates instantly, because the scan keeps every resource's full tag set.
4. **Resource types.** A checklist of every resource type, grouped by service.
   - **By default only main resource types are ticked:** instances, volumes, network interfaces, security groups, launch templates, VPCs, NAT gateways, buckets, databases, Lambda, load balancers, EKS clusters and nodegroups, ECS/ECR, queues, topics, secrets, KMS keys and so on.
   - **Fine-grained types** are marked `· fine-grained` and start unticked: AMIs, snapshots, subnets, route tables, NACLs, internet gateways, target groups, log groups, IAM, CloudFormation, EKS add-ons/Fargate profiles. Tick them when you need them.
   - **Main only** resets to the default.
   - Click a service to toggle all of its types, or expand it to pick individual types (for example only `ec2 › volume`).
   - Your own custom types appear under **★ custom**. See [Custom resource types](#custom-resource-types) below.
   - The "Tagging API catch-all" option (**off by default**, because it is very granular) also picks up every *already-tagged* resource of any other type. After a scan, the log lists the types that only the Tagging API found.
5. **Scan.** The table shows one column per required key:
   - the existing value, or `✗ missing`, `✗ (empty)` or `✗ program=x` (wrong case)
   - a **Current tags** column with every tag the resource has now (scroll right). The line under the table shows the full tag list of the highlighted row.
   - red rows are non-compliant, green rows are compliant, yellow rows have a pending change
   - The filter box and the "Only show non-compliant" toggle narrow the list, and you can click a column header to sort.
   - **Types ▾** opens a checklist of every resource type in the results, with "non-compliant / total" counts. Untick types to hide them from the list, and the button shows "Types: 4 of 12". **Only types with gaps** ticks just the types that still need tags.
   - **Hide pod resources** is on by default (PVC volumes, per-pod interfaces, load balancers for Kubernetes Services). Nodes and their volumes and interfaces are always shown, with an **EKS cluster** column. See [EKS and Kubernetes](#eks-and-kubernetes).
   - "Set on all shown" and Export only affect the rows currently shown, so filter first and then tag.
6. **Set values.** Tick the resources you want with the checkbox at the left of each row. Clicking the header checkbox ticks (or unticks) every shown row, and Space ticks the highlighted rows. Choose a key and type a value. Then:
   - **Set on ticked** sets it on the ticked rows that are shown. If nothing is ticked, it uses the highlighted rows instead.
   - **Set on all shown** sets it on every row in the list. Use the filter first, for example `ec2:volume` or `us-gov-west-1`.
   - **Clear pending (ticked)** removes pending values from the ticked rows.
   - **Untick all** clears every tick (also on the right-click menu).
   - **Tick a whole EKS cluster** (dropdown), or right-click any row in a cluster and choose *Tick everything in EKS cluster …*: ticks the cluster, its nodegroups, nodes, node volumes and interfaces, launch templates, Auto Scaling groups and security groups in one go. Pod resources stay out. This ignores **Only show non-compliant**: ticked rows always stay in the list, compliant or not. Rows hidden by the filter box or **Types** are not ticked. To overwrite values that are already there, also untick **only where missing**.
   - **Double-click a tag cell** to edit a single resource.
   - With "only where missing" ticked, resources that already have a value for that key are left alone.
7. **Apply.** First the full plan is written to the log: each resource with its change (`Program: (missing) -> ALPHA`), then the exact AWS CLI commands equivalent to the API calls the tool will make, for example `aws resourcegroupstaggingapi tag-resources --region us-east-1 --resource-arn-list arn:… --tags Program=ALPHA` and `aws iam tag-role --role-name app-role --tags Key=Program,Value=ALPHA`. Then a confirmation dialog asks before anything changes. **Show plan in log** prints the plan without applying. If the Tagging API rejects a resource during apply, the log shows the service-specific command used instead. Tick **Dry run** to simulate without changing anything. Failed changes stay pending, with the error shown in the log. Each apply writes a `tag-apply-results_<acct>_<time>.csv` file to the current folder.
8. **Export CSV.** Saves the rows currently shown, with value, status and pending value for each key.

## Custom resource types

If AWS releases a new service, or you need a type the tool doesn't cover, you can add it yourself. A custom type is a saved AWS CLI–style command, and it is re-run on every scan.

**In the GUI:** go to **Resource types → New type…**

| Field | Example |
|---|---|
| Name (`service:type`, shown in the Type column) | `sagemaker:notebook-instance` |
| AWS command | `aws sagemaker list-notebook-instances` |
| Scope | Regional (run in each scanned region) or Global (run once) |

Click **Test** to run the command in one region. The preview shows:
- how many items it found
- the ID, name, ARN and tags it found for each item
- the raw JSON of the first item, so you can see the real field names

Any auto-detected fields are filled in for you to check. Then click **Save**.

To change a type later, use **Edit…** or double-click it in the tree. Use **Delete** to remove it. **Start from example** pre-fills a few working examples:
- running EC2 instances only, using `--filters`
- OpenSearch domains, using an ARN template
- ElastiCache clusters
- SageMaker notebooks
- DynamoDB tables

**How the command runs**
- It goes through boto3 using the same profile, region and credentials as the scan. **The AWS CLI does not need to be installed.**
- Normal CLI syntax works:
  - `--filters Name=instance-state-name,Values=running`
  - JSON values: `--filters '[{"Name":"vpc-id","Values":["vpc-1"]}]'`
  - lists: `--owner-ids self`
  - booleans: `--flag` and `--no-flag`
  - `s3api` instead of `s3`
- `--region`, `--profile`, `--output`, `--query` and paging options are ignored, because the scanner supplies them.
- Results are paginated automatically.
- **Only read-only operations are allowed** (`list-*`, `describe-*`, `get-*`, `search-*`, `lookup-*`, `batch-get-*`). The command runs in every region you scan, so anything that could make changes is rejected when you save it and again when it runs.
- Typos get suggestions, for example "`describe-instancez` isn't an operation of ec2. Try: describe-instances, …". The same goes for unknown `--params`.
- The service list comes from your installed `botocore`. To get a brand-new service, upgrade boto3 with `pip install -U boto3`.

**How each result becomes a resource.** Leave a field blank to auto-detect it. Test shows what was picked.

| Field | Meaning |
|---|---|
| Items path | Where the list is in the response. Usually auto. For nested lists use dots, for example `Reservations.Instances` for `describe-instances`. |
| ID field | Auto-detected from the operation name, for example `describe-cache-clusters` → `CacheClusterId`. |
| Name field | Blank means the `Name` tag is used. |
| ARN field | For example `FunctionArn`. Auto-detected if the output has an ARN. |
| ARN template | Used when the output has no ARN, for example `arn:{partition}:es:{region}:{account}:domain/{DomainName}`. Available variables: `{partition} {region} {account} {id} {name}` plus any top-level field of the item. |

**Tags** are read from the item itself if it has `Tags`, `TagList` or `TagSet`. Otherwise they're looked up by ARN through the Tagging API, which works for any taggable resource, even never-tagged ones.

**Applying tags** to custom types uses `tag:TagResources` with the ARN. A resource **must have an ARN** (an ARN field or ARN template) to be tagged; the Test preview warns you if it doesn't.

**Where custom types are stored.** They're saved in `custom_types.json` next to the scripts. You can set a different path with the `AWS_TAG_AUDIT_TYPES` environment variable or `--types-file`.

The file is git-ignored by default, because commands can contain account-specific filters. To share your types, review the file and commit it deliberately, for example as `team_types.json`, which others load with `--types-file` or `AWS_TAG_AUDIT_TYPES`. It's plain JSON and can be edited by hand:

```json
{"version": 1, "types": [
  {"name": "opensearch:domain", "command": "aws opensearch list-domain-names", "scope": "regional",
   "items_path": "DomainNames", "id_field": "DomainName",
   "arn_template": "arn:{partition}:es:{region}:{account}:domain/{DomainName}"}
]}
```

**The CLI uses the same file:**

```bash
python aws_tag_audit.py types                                      # list built-in + custom types
python aws_tag_audit.py types --test opensearch:domain --region us-gov-west-1   # dry-run one type
python aws_tag_audit.py scan --services opensearch:domain ec2:volume            # scan only these types
```

## CLI

### 1. Scan

```bash
python aws_tag_audit.py scan                                  # all enabled regions
python aws_tag_audit.py scan --profile work --region us-gov-west-1
python aws_tag_audit.py scan --regions us-east-1 us-west-2 --services ec2 s3 rds
python aws_tag_audit.py scan --key Program Owner CostCenter   # require several keys
python aws_tag_audit.py scan --all-types                       # include fine-grained types too
python aws_tag_audit.py scan --services ec2:snapshot           # just one (any) type
```

**By default `scan` covers main resource types only**, the same set the GUI ticks by default: instances, volumes, network interfaces, security groups, VPCs, buckets, databases, Lambda, load balancers, EKS clusters and nodegroups and so on. `--all-types` adds the fine-grained ones (AMIs, snapshots, subnets, route tables, target groups, log groups, IAM, EKS add-ons). `types` lists which is which, with fine-grained types marked `*`.

`--key` defaults to `Program`. With several keys, a resource is listed if it is missing **any** of them, and the summary shows a count for each key per resource type.

This writes three files to `./tag-audit-output/`:

| File | Contents |
|---|---|
| `<acct>_<time>_untagged.csv` | **The list.** One row per resource missing a key. It starts with one empty column per key for you to fill in (`Program`, `Owner`, …), then a `<key>_status` column for each key. |
| `<acct>_<time>_inventory.csv` | Every resource found, with a `has_<key>` yes/no column per key and a `k8s_workload` column |
| `<acct>_<time>_scan_errors.csv` | Collectors that failed, usually AccessDenied or a service that doesn't exist in that region |

Each `<key>_status` column says where that key stands:
- `ok`: the resource already has it. Leave the value blank and nothing changes.
- `missing`: no such key at all
- `empty-value`: the key is there but the value is blank
- `wrong-case-key: program`: the key is spelled with different casing. AWS tag keys are case-sensitive, so this one doesn't count as tagged.

The scan also prints counts by resource type and by region.

### How resources are found

Two sources, merged by ARN:

1. **Direct per-service enumeration.** This is the only way to find resources that have *never* been tagged. It covers:
   - EC2: instances, volumes, snapshots, AMIs, SGs, VPCs, subnets, ENIs, EIPs, IGWs, NAT GWs, route tables, NACLs, DHCP options, key pairs, launch templates, VPC endpoints, TGWs
   - S3, EFS, RDS (instances, clusters, manual snapshots), DynamoDB
   - Lambda, ECS, EKS, ECR, Auto Scaling, SNS, SQS, Step Functions
   - ALB/NLB, target groups, classic ELB, Route 53 zones
   - KMS (customer-managed keys), Secrets Manager, CloudWatch log groups, CloudFormation stacks
   - IAM roles, users, and customer-managed policies
2. **The Resource Groups Tagging API** (`tag:GetResources`). This covers almost every service, but it **only returns resources that have, or once had, at least one tag**. It's a catch-all for services that aren't enumerated directly, and it's **off by default** because it pulls in every tagged thing at the finest grain. Turn it on with `--tagging-api`, or the checkbox in the GUI.

Rows found only through the Tagging API have `source=tagging-api`.

Some things are skipped on purpose because you can't tag them yourself: AWS-managed KMS keys, service-linked IAM roles, and terminated or deleted resources.

> Note: ENIs, default VPCs, default SGs and similar resources will show up too. If you don't want to tag them, leave their rows blank (blank rows are skipped), or filter them out with `--services` at apply time.

### 2. Tag (value supplied by you)

There are three ways to supply values. You can mix them.

**A. Fill in the CSV (best when there are many resources).** Open `_untagged.csv` in Excel, type a value in the `Program` column for each row you want tagged, save it as CSV, and run:

```bash
python aws_tag_audit.py apply --csv tag-audit-output/123456789012_..._untagged.csv --dry-run   # preview
python aws_tag_audit.py apply --csv tag-audit-output/123456789012_..._untagged.csv             # do it
```

**B. Interactive: prompt for each resource.**

```bash
python aws_tag_audit.py apply --csv ..._untagged.csv --interactive
```
```
[3/142] ec2:instance  us-gov-west-1  web-01  (i-0abc123)
      tags: Name=web-01, Owner=jsmith
    Program value [. = ALPHA]:
```
- `Enter`: skip this resource
- `.`: use the same value as the previous one
- `.all`: use the previous value for every remaining resource of the same type (for example all remaining `ec2:volume`)
- `q`: stop asking and go to the confirmation step

Your answers are saved to `..._untagged_answers.csv`, so you can quit and resume later with `apply --csv ..._answers.csv -i`.

**C. One value for everything (or a filtered subset):**

```bash
python aws_tag_audit.py apply --csv ..._untagged.csv --value ALPHA --services ec2:volume ec2:snapshot --regions us-east-1
# several keys: give each one
python aws_tag_audit.py apply --csv ..._untagged.csv --value Program=ALPHA --value Owner=platform --services eks
```

Before anything changes, `apply` always prints the plan: each resource with its change (`Program: (missing) -> ALPHA`) and the AWS CLI commands equivalent to the API calls it will make. Then it asks y/N. Use `--yes` to skip that question; `--dry-run` prints the plan and changes nothing.

It also **refuses to run if the CSV is from a different account** than the one you're logged into.

### How the tag is applied

- It only *adds or overwrites* the `Program` key. Other tags are never touched. For S3, existing tags are read and merged first, because `PutBucketTagging` would otherwise replace them all.
- It uses `tag:TagResources` first, in batches of 20 per region.
- If that fails for a resource, it falls back to the service's own API: EC2 `CreateTags`, IAM `TagRole`/`TagUser`/`TagPolicy`, Route 53, S3, Logs, Lambda, SQS.
- Every change ends up in `..._results_<time>.csv`, one row per resource and key, with `status` (`tagged` or `failed`), `tag_key` and a `message`. Feed that results file straight back into `apply --csv` to retry **only the failed changes**.
- `apply` finds the key columns in the CSV by itself. Pass `--key` only to limit it, for example `--key Owner`. `--interactive` asks key by key.

Tag values are limited to 256 characters, using letters, numbers, spaces and `_ . : / = + - @`.

### Verify

Run `scan` again. Anything you tagged will be gone from the untagged list.

## EKS and Kubernetes

The tool covers an EKS cluster's **AWS infrastructure**, and skips the things that exist only because of what runs **inside** the cluster.

**Listed** (main types, ticked by default). Each one gets an **EKS cluster** column, so you can see what belongs to which cluster, and typing the cluster name in the filter box shows just that cluster. Volumes and network interfaces attached to a node count as part of that node's cluster even when they have no cluster tags of their own. To tag everything in a cluster at once, use **Tick a whole EKS cluster** in the GUI, then **Set on ticked**.

| Resource | Type |
|---|---|
| The cluster | `eks:cluster` |
| Managed nodegroups | `eks:nodegroup` |
| Nodes | `ec2:instance` |
| Node volumes (root/data) | `ec2:volume` |
| Node network interfaces, including the VPC CNI's per-node `aws-K8S-…` interfaces | `ec2:network-interface` |
| Nodegroup launch templates, Auto Scaling groups, cluster security group | `ec2:launch-template`, `autoscaling`, `ec2:security-group` |

Fargate profiles and add-ons are available, but they're fine-grained and unticked by default.

**Hidden: pod and in-cluster resources.** These are recognised by the tags and descriptions Kubernetes controllers put on them:

| Hidden | How it's recognised |
|---|---|
| PersistentVolume EBS/EFS/FSx volumes (PVCs) | `kubernetes.io/created-for/…`, `CSIVolumeName`, `ebs.csi.aws.com/…` tags |
| Per-pod network interfaces (security groups for pods) | `branch` interface type, `aws-k8s-branch-eni` description, `vpcresources.k8s.aws/…` tags |
| Load balancers, target groups and security groups created for Kubernetes Services/Ingresses | `elbv2.k8s.aws/…`, `ingress.k8s.aws/…`, `service.k8s.aws/…`, `kubernetes.io/service-name` tags |
| EKS pod identity associations | resource type |

**Images are not scanned by default:** AMIs (`ec2:image`) and snapshots are fine-grained types. Tick them, or use `--all-types`, if you ever need them.

**Network interfaces that AWS services create for themselves are left out completely.** These are "requester-managed" interfaces for load balancers, NAT gateways, Lambda, RDS, VPC endpoints and so on. They belong to those services, not to you or your nodes.

To see the hidden pod resources:
- **GUI:** untick **Hide pod resources**. The counts line shows how many are hidden, and the log lists them by kind.
- **CLI:** they're left out of `*_untagged.csv`, and the summary says how many. `--include-k8s-workloads` lists them. The inventory CSV always includes them, with a `k8s_workload` column that gives the reason, and every CSV has an `eks_cluster` column.

Tagging EKS resources uses the Tagging API first, then the EKS `TagResource` API as a fallback.

## Good to know

These come from testing against a real account:

- **Blocked regions.** If an SCP limits which regions you can use, or a region isn't opted in, every call there is denied. The scan reports these in one line, "Regions where almost every call was denied: …", instead of hundreds of AccessDenied errors. All other errors are still listed, and the full detail is in `*_scan_errors.csv`.
- **Resources that can't be tagged are left out**, even when the Tagging API still returns them: KMS keys pending deletion or managed by AWS, terminated instances, service-linked roles, and deleted NAT gateways.
- **Duplicates.** When the same resource is found more than once, the built-in check wins, then your custom type, then the Tagging API catch-all.
- **DynamoDB** allows only one tag update at a time per table. Throttled or "being updated" tag errors are retried automatically with backoff. Its tags can take about 10 seconds to show up, so a rescan right after applying may briefly show the old value.

## IAM permissions

**Scan.** The AWS-managed `ReadOnlyAccess` policy is enough. Without it you need at least `tag:GetResources` plus the Describe/List/ListTags calls for each service. Anything you can't read just appears in `scan_errors.csv`, and the rest of the scan continues.

**Apply.** You need `tag:TagResources` **plus the per-service tag permission** for each resource type, because the Tagging API checks those too:

```
ec2:CreateTags, s3:GetBucketTagging, s3:PutBucketTagging, rds:AddTagsToResource,
lambda:TagResource, dynamodb:TagResource, sns:TagResource, sqs:TagQueue,
ecr:TagResource, ecs:TagResource, eks:TagResource, autoscaling:CreateOrUpdateTags,
elasticloadbalancing:AddTags, elasticfilesystem:TagResource, kms:TagResource,
secretsmanager:TagResource, logs:TagLogGroup, logs:TagResource, cloudformation:TagResource,
states:TagResource, iam:TagRole, iam:TagUser, iam:TagPolicy, route53:ChangeTagsForResource
```

SCPs or tag policies in your org may block some of these. Those resources show up as `failed` in the results with the AWS error message.

## GovCloud / isolated regions

The script reads the partition from your STS identity (`aws`, `aws-us-gov`, `aws-iso`, `aws-iso-b`), so ARNs and the IAM/Route 53 "global" region are correct for that partition. Pass `--region` for a region that exists in your partition if your profile doesn't set one.

- If your environment uses a custom CA bundle, set `AWS_CA_BUNDLE=/path/to/ca.pem`.
- If the network is air-gapped, bring a `boto3` wheel along (`pip download boto3 -d wheels/`, then `pip install --no-index --find-links wheels boto3`).
- Use a recent `botocore` so it knows the endpoints for your partition.

Services that aren't available in a region are silently skipped (`ServiceNotInRegion` in the errors file).

## Options

```
common:  --profile  --region  --key K1 [K2 ...]  --regions r1 r2  --services ec2 s3 ec2:volume eks  --workers 8  --types-file F
types:   --test NAME
scan:    --all-types   --tagging-api   --include-k8s-workloads   --exclude-services logs ec2:volume   --out DIR
apply:   --csv FILE  -i/--interactive  --value [KEY=]V (repeatable)  --overwrite-csv-values  --dry-run  -y/--yes
```

`--key` takes one or more tag keys, for example `--key Program Owner CostCenter`. Each gets its own CSV column.
