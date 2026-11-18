# EC2 Manager

FastAPI backend + browser dashboard for managing EC2 instances across 4 regions
(us-east-1, us-west-2, ap-south-1, eu-west-1), using real boto3 calls against
your AWS account.

## Project layout

```
ec2-manager/
├── app/
│   ├── __init__.py
│   ├── ec2_core.py      # AWS logic (AMI/subnet/SG/key matrices, create/list/start/stop/terminate)
│   └── main.py          # FastAPI routes, serves the frontend
├── frontend/
│   └── index.html       # Dashboard + Launch Instance UI (matches your screenshots)
├── requirements.txt
└── README.md
```

## 1. AWS credentials (required — this app makes real API calls)

Configure credentials any of these ways:

```bash
aws configure
# or
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
```

The IAM user/role needs at minimum:

**EC2:** `ec2:RunInstances`, `ec2:DescribeInstances`, `ec2:StartInstances`,
`ec2:StopInstances`, `ec2:TerminateInstances`, `ec2:DescribeSubnets`,
`ec2:CreateSecurityGroup`, `ec2:DescribeSecurityGroups`, `ec2:AuthorizeSecurityGroupIngress`

**EFS (for persistent storage):** `elasticfilesystem:CreateFileSystem`,
`elasticfilesystem:DescribeFileSystems`, `elasticfilesystem:CreateMountTarget`,
`elasticfilesystem:DescribeMountTargets`, `elasticfilesystem:DeleteMountTarget`,
`elasticfilesystem:DeleteFileSystem`, `elasticfilesystem:TagResource`

## 2. Set up the environment

```bash
cd ec2-manager
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Before running — check the lookup matrices

`app/ec2_core.py` hardcodes AMI IDs, subnet IDs, security group IDs, and key
pair names per region (copied from your original `functions.py`). **These are
account/region-specific and will likely need updating for your AWS account:**

- AMI IDs go stale — verify current ones in the EC2 console per region.
- Subnet IDs, security group IDs, and key pair names must exist in *your*
  account/VPC, or `run_instances` will fail with a `ClientError`.
- The `eu-west-1` key pair in the original code (`key-pair-europe-ireland-eu-west-2`)
  has a name that looks copy-pasted from `eu-west-2` — double check this one
  particularly if instance creation fails in `eu-west-1`.

## 4. Set a login (username & password)

The dashboard and every API route are protected by HTTP Basic Auth. Set the
credentials as environment variables before running:

```bash
export APP_USERNAME=your_username
export APP_PASSWORD=your_strong_password
```

If these aren't set, the app falls back to `admin` / `admin` and prints a
warning — fine for a quick localhost test, but change it before running
anywhere reachable over the network.

## 5. Run it

```bash
uvicorn app.main:app --reload --port 8000
```

Open **http://127.0.0.1:8000** — your browser will prompt for the
username/password you set above. The FastAPI app serves the dashboard
directly, so no separate frontend server is needed.

## API endpoints (if you want to use the API standalone)

| Method | Path                          | Purpose                                  |
|--------|-------------------------------|-------------------------------------------|
| GET    | `/api/regions`                | List supported regions                    |
| GET    | `/api/os-options`             | List supported OS types                   |
| GET    | `/api/instances?region=X`     | List instances in a region                |
| GET    | `/api/instances/all-regions`  | List instances across all 4 regions       |
| POST   | `/api/instances`              | Create instance `{name, os_type, region}` |
| POST   | `/api/instances/start`        | Start `{instance_id, region}`             |
| POST   | `/api/instances/stop`         | Stop `{instance_id, region}`              |
| DELETE | `/api/instances/{id}?region=` | Terminate an instance                     |

Interactive API docs: **http://127.0.0.1:8000/docs**

## Persistent storage (EFS) — how it works

**At launch:**
1. A new EFS filesystem is created (encrypted, general purpose, bursting
   throughput), tagged `OriginInstanceName` / `ManagedBy=ec2-manager` /
   `Status=attached`.
2. A security group (`efs-access-sg-auto`, created once per VPC and reused)
   allows inbound NFS (port 2049) only from the launching instance's own
   security group — not open to the world.
3. A mount target is created in the instance's subnet.
4. The instance's user-data script installs `amazon-efs-utils` (Amazon Linux:
   via `yum`; Ubuntu: built from source, which takes a minute or two on first
   boot) and mounts the filesystem at `/mnt/data`, persisted in `/etc/fstab`
   so it survives reboots.
5. **Windows is not supported** for auto-mount — the EFS mount helper is
   Linux-only. Storage is skipped automatically if you pick Windows.

**At termination:** the instance is destroyed as normal, but the EFS
filesystem is left completely alone — only its `Status` tag flips from
`attached` to `orphaned`. Nothing about the filesystem or its data changes.

**Reusing storage:** open the **Storage** tab to see every filesystem this
app has created, across all 4 regions, with its status and origin instance
name. Orphaned filesystems show a **"Relaunch with this"** button that jumps
to the Launch form with that filesystem pre-selected — the new instance mounts
the *same* EFS at `/mnt/data`, picking up where the old one left off.

**Deleting storage permanently:** the Storage tab has a **Delete** button per
filesystem. This is the only way filesystem data is ever removed — a separate,
deliberate action, never a side effect of terminating an instance.

**Caveat:** if the same filesystem gets attached to two instances at once, or
writes aren't quiesced before termination, NFS behaves like any shared network
filesystem — no extra conflict protection is added here. Treat "one active
instance per filesystem at a time" as the assumption this app makes.

## Notes on what changed vs. the original scripts

- Same lookup matrices and boto3 calls as `functions.py` — logic is unchanged,
  just wrapped in FastAPI request handlers instead of CLI `input()` prompts.
- **macOS was dropped** as an OS option (no AMI entries exist for it, and AWS
  doesn't offer standard macOS AMIs the way it does Linux/Windows).
- Errors from AWS (`ClientError`, missing credentials, network issues) are
  caught and returned as JSON with a readable message instead of printed to
  console.
