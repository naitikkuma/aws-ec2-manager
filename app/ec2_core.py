"""
AWS EC2 Core Logic Library
Refactored from the original functions.py for use in a FastAPI backend.
All AWS calls use real boto3 clients (no mocking).
"""

import re
import threading

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError

# ==============================================================================
# STATIC UI METADATA (region/OS labels only — AMI/subnet/SG/key-pair are now
# resolved dynamically per user by querying their AWS account, see the
# "LIVE AWS RESOURCE LOOKUPS" section below).
# ==============================================================================

# Owner IDs / name-pattern filters used to search for a sensible set of
# candidate AMIs per OS family. These are just search hints, not fixed IDs —
# the actual AMI IDs come back from a live describe_images call.
AMI_SEARCH_FILTERS = {
    "amazon-linux": {
        "owners": ["amazon"],
        "name_patterns": ["al2023-ami-*-x86_64", "amzn2-ami-hvm-*-x86_64-gp2"],
    },
    "ubuntu": {
        "owners": ["099720109477"],  # Canonical
        "name_patterns": ["ubuntu/images/hvm-ssd*/ubuntu-*-amd64-server-*"],
    },
    "windows": {
        "owners": ["amazon"],
        "name_patterns": ["Windows_Server-2022-English-Full-Base", "Windows_Server-2019-English-Full-Base"],
    },
}

# Human-friendly region labels for the UI
REGION_LABELS = {
    "us-east-1": "US East (N. Virginia)",
    "us-west-2": "US West (Oregon)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "eu-west-1": "Europe (Ireland)",
}

# OS options (macOS dropped — not offered as a standard EC2 AMI type)
OS_LABELS = {
    "amazon-linux": "Amazon Linux",
    "ubuntu": "Ubuntu",
    "windows": "Windows",
}

VALID_REGIONS = set(REGION_LABELS.keys())
VALID_OS = set(OS_LABELS.keys())


# ==============================================================================
# LIVE AWS RESOURCE LOOKUPS
# (dynamic replacements for the old hardcoded matrices — every user sees
# their own account's AMIs/subnets/security groups/key pairs)
# ==============================================================================

def list_amis(region: str, os_type: str) -> list:
    """Query real AMIs available to this account for the given OS family."""
    if os_type not in AMI_SEARCH_FILTERS:
        raise EC2Error(f"Unsupported OS type: {os_type}")

    spec = AMI_SEARCH_FILTERS[os_type]
    client = _client(region)
    try:
        response = client.describe_images(
            Owners=spec["owners"],
            Filters=[
                {"Name": "name", "Values": spec["name_patterns"]},
                {"Name": "state", "Values": ["available"]},
                {"Name": "architecture", "Values": ["x86_64"]},
            ],
        )
    except Exception as e:
        raise _handle_aws_exception(e, "look up AMIs")

    images = sorted(
        response.get("Images", []),
        key=lambda i: i.get("CreationDate", ""),
        reverse=True,
    )
    return [
        {
            "ami_id": img["ImageId"],
            "name": img.get("Name", img["ImageId"]),
            "description": img.get("Description", ""),
            "creation_date": img.get("CreationDate", ""),
        }
        for img in images[:15]
    ]


def list_subnets(region: str) -> list:
    """Query the real subnets available in this account/region."""
    client = _client(region)
    try:
        response = client.describe_subnets()
    except Exception as e:
        raise _handle_aws_exception(e, "look up subnets")

    subnets = []
    for s in response.get("Subnets", []):
        name = next((t["Value"] for t in s.get("Tags", []) if t["Key"] == "Name"), "")
        subnets.append({
            "subnet_id": s["SubnetId"],
            "name": name,
            "vpc_id": s["VpcId"],
            "availability_zone": s.get("AvailabilityZone", ""),
            "cidr_block": s.get("CidrBlock", ""),
            "default_for_az": s.get("DefaultForAz", False),
        })
    return subnets


def list_security_groups(region: str, vpc_id: str = None) -> list:
    """Query the real security groups available in this account/region,
    optionally scoped to a specific VPC (e.g. once a subnet is chosen)."""
    client = _client(region)
    filters = [{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else []
    try:
        response = client.describe_security_groups(Filters=filters)
    except Exception as e:
        raise _handle_aws_exception(e, "look up security groups")

    return [
        {
            "security_group_id": sg["GroupId"],
            "name": sg.get("GroupName", ""),
            "description": sg.get("Description", ""),
            "vpc_id": sg.get("VpcId", ""),
        }
        for sg in response.get("SecurityGroups", [])
    ]


def list_key_pairs(region: str) -> list:
    """Query the real key pairs available in this account/region."""
    client = _client(region)
    try:
        response = client.describe_key_pairs()
    except Exception as e:
        raise _handle_aws_exception(e, "look up key pairs")

    return [
        {"key_name": kp["KeyName"], "key_pair_id": kp.get("KeyPairId", "")}
        for kp in response.get("KeyPairs", [])
    ]


# ------------------------------------------------------------------------------
# CACHED boto3 CLIENTS
#
# boto3.client() is surprisingly expensive: it parses the botocore service
# model and resolves credentials on every call. The old code built a fresh
# client for every dropdown load and every list request, which was the main
# source of the UI feeling slow. We now build each (service, region) client
# once and reuse it. boto3 clients are thread-safe for making API calls, so the
# cache is safe to share across the ThreadPoolExecutor used for all-region
# fan-out; a lock guards only the (non-thread-safe) construction step.
# ------------------------------------------------------------------------------

_SESSION = boto3.session.Session()
_CLIENT_CACHE = {}
_CLIENT_LOCK = threading.Lock()

# Fail fast instead of hanging the UI when credentials/network are misconfigured.
_BOTO_CONFIG = Config(
    retries={"max_attempts": 3, "mode": "standard"},
    connect_timeout=5,
    read_timeout=15,
    max_pool_connections=25,
)


def _get_client(service: str, region: str):
    """Return a cached boto3 client for (service, region), creating it once."""
    key = (service, region)
    client = _CLIENT_CACHE.get(key)
    if client is None:
        with _CLIENT_LOCK:
            client = _CLIENT_CACHE.get(key)
            if client is None:
                client = _SESSION.client(service, region_name=region, config=_BOTO_CONFIG)
                _CLIENT_CACHE[key] = client
    return client


def _client(region: str):
    return _get_client("ec2", region)


def create_key_pair(region: str, key_name: str, key_type: str = "rsa") -> dict:
    """Create a NEW key pair in AWS and return its private key material. AWS only
    ever exposes the private key at creation time, so this is the single moment
    the caller can download the .pem."""
    if region not in VALID_REGIONS:
        raise EC2Error(f"Unsupported region: {region}")
    key_name = (key_name or "").strip()
    if not key_name:
        raise EC2Error("A key pair name is required.")
    if key_type not in ("rsa", "ed25519"):
        key_type = "rsa"

    client = _client(region)
    try:
        resp = client.create_key_pair(KeyName=key_name, KeyType=key_type, KeyFormat="pem")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "InvalidKeyPair.Duplicate":
            raise EC2Error(
                f"A key pair named '{key_name}' already exists in {region}. "
                "Pick a different name (the existing key's private file can't be re-downloaded)."
            )
        raise _handle_aws_exception(e, "create the key pair")
    except Exception as e:
        raise _handle_aws_exception(e, "create the key pair")

    return {
        "key_name": resp["KeyName"],
        "key_pair_id": resp.get("KeyPairId", ""),
        "fingerprint": resp.get("KeyFingerprint", ""),
        "private_key": resp["KeyMaterial"],  # the .pem file contents
    }


# Default SSH usernames per managed OS family (used to prefill the SSH dialog).
SSH_USERNAMES = {
    "amazon-linux": "ec2-user",
    "ubuntu": "ubuntu",
    "windows": "administrator",
}


class EC2Error(Exception):
    """Raised for any AWS/boto3 failure, carrying a user-friendly message."""
    def __init__(self, message: str, detail: str = ""):
        self.message = message
        self.detail = detail
        super().__init__(message)


def _handle_aws_exception(e: Exception, action: str) -> EC2Error:
    if isinstance(e, NoCredentialsError):
        return EC2Error("AWS credentials not found.", str(e))
    if isinstance(e, EndpointConnectionError):
        return EC2Error(f"Could not reach AWS endpoint while trying to {action}.", str(e))
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "Unknown")
        msg = e.response.get("Error", {}).get("Message", str(e))
        return EC2Error(f"AWS rejected the request ({code}) while trying to {action}.", msg)
    return EC2Error(f"Unexpected error while trying to {action}.", str(e))


# ==============================================================================
# MAIN OPERATIONS
# ==============================================================================

def ec2_create(
    region: str,
    os_type: str,
    name: str,
    ami_id: str,
    subnet_id: str,
    security_group_id: str,
    key_name: str,
    instance_type: str = "t3.small",
    user_data: str = None,
    extra_tags: dict = None,
) -> dict:
    if region not in VALID_REGIONS:
        raise EC2Error(f"Unsupported region: {region}")
    if os_type not in VALID_OS:
        raise EC2Error(f"Unsupported OS type: {os_type}")
    if not ami_id:
        raise EC2Error("An AMI must be selected.")
    if not subnet_id:
        raise EC2Error("A subnet must be selected.")
    if not security_group_id:
        raise EC2Error("A security group must be selected.")
    if not key_name:
        raise EC2Error("A key pair must be selected.")

    final_ami = ami_id
    final_subnet = subnet_id
    final_sg = security_group_id
    final_key = key_name

    tags = [
        {"Key": "Name", "Value": name or "unnamed-instance"},
        {"Key": "ManagedOS", "Value": os_type},
    ]
    if extra_tags:
        tags.extend({"Key": k, "Value": v} for k, v in extra_tags.items())

    client = _client(region)
    run_kwargs = dict(
        ImageId=final_ami,
        MinCount=1,
        MaxCount=1,
        InstanceType=instance_type,
        KeyName=final_key,
        SecurityGroupIds=[final_sg],
        SubnetId=final_subnet,
        TagSpecifications=[{"ResourceType": "instance", "Tags": tags}],
    )
    if user_data:
        run_kwargs["UserData"] = user_data

    try:
        response = client.run_instances(**run_kwargs)
        instance = response["Instances"][0]
        return {
            "instance_id": instance["InstanceId"],
            "region": region,
            "os": os_type,
            "ami": final_ami,
            "subnet": final_subnet,
            "security_group": final_sg,
            "key_pair": final_key,
            "state": instance["State"]["Name"],
            "vpc_id": _get_vpc_id_for_subnet(client, final_subnet),
        }
    except Exception as e:
        raise _handle_aws_exception(e, "create the instance")


def _get_vpc_id_for_subnet(client, subnet_id: str) -> str:
    try:
        resp = client.describe_subnets(SubnetIds=[subnet_id])
        return resp["Subnets"][0]["VpcId"]
    except Exception:
        return ""


def ec2_list(region: str) -> list:
    if region not in VALID_REGIONS:
        raise EC2Error(f"Unsupported region: {region}")

    client = _client(region)
    try:
        response = client.describe_instances()
    except Exception as e:
        raise _handle_aws_exception(e, "list instances")

    instances = []
    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
            name = tags.get("Name", "N/A")
            managed_os = tags.get("ManagedOS", "")

            is_windows = instance.get("Platform") == "windows"
            ssh_user = SSH_USERNAMES.get(managed_os, "ec2-user")

            instances.append({
                "name": name,
                "instance_id": instance.get("InstanceId"),
                "state": instance.get("State", {}).get("Name", "N/A"),
                "instance_type": instance.get("InstanceType", "N/A"),
                "availability_zone": instance.get("Placement", {}).get("AvailabilityZone", "N/A"),
                "public_ip": instance.get("PublicIpAddress", "—"),
                "public_dns": instance.get("PublicDnsName", ""),
                "key_name": instance.get("KeyName", ""),
                "os": managed_os,
                "is_windows": is_windows,
                "ssh_user": ssh_user,
                "region": region,
            })
    return instances


def get_instance_tags(instance_id: str, region: str) -> dict:
    """Returns a {TagKey: TagValue} dict for a single instance, used to look up
    its associated EFS filesystem before termination."""
    if region not in VALID_REGIONS:
        raise EC2Error(f"Unsupported region: {region}")
    client = _client(region)
    try:
        response = client.describe_instances(InstanceIds=[instance_id])
    except Exception as e:
        raise _handle_aws_exception(e, "look up the instance")

    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            return {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    return {}


def ec2_start(instance_id: str, region: str) -> dict:

    if region not in VALID_REGIONS:
        raise EC2Error(f"Unsupported region: {region}")
    client = _client(region)
    try:
        client.start_instances(InstanceIds=[instance_id])
        return {"instance_id": instance_id, "action": "start", "status": "requested"}
    except Exception as e:
        raise _handle_aws_exception(e, "start the instance")


def ec2_stop(instance_id: str, region: str) -> dict:
    if region not in VALID_REGIONS:
        raise EC2Error(f"Unsupported region: {region}")
    client = _client(region)
    try:
        client.stop_instances(InstanceIds=[instance_id])
        return {"instance_id": instance_id, "action": "stop", "status": "requested"}
    except Exception as e:
        raise _handle_aws_exception(e, "stop the instance")


def ec2_terminate(instance_id: str, region: str) -> dict:
    if region not in VALID_REGIONS:
        raise EC2Error(f"Unsupported region: {region}")
    client = _client(region)
    try:
        client.terminate_instances(InstanceIds=[instance_id])
        return {"instance_id": instance_id, "action": "terminate", "status": "requested"}
    except Exception as e:
        raise _handle_aws_exception(e, "terminate the instance")


# ==============================================================================
# SSH CONNECTIVITY
#
# The #1 reason a freshly launched instance "won't connect" is that the chosen
# security group (often "default") has no inbound rule for TCP 22, so SSH just
# times out. These helpers let the UI diagnose that and, on explicit request,
# open the port.
# ==============================================================================

_CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")


def _find_instance(client, instance_id: str) -> dict:
    try:
        resp = client.describe_instances(InstanceIds=[instance_id])
    except Exception as e:
        raise _handle_aws_exception(e, "look up the instance")
    for reservation in resp.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            return instance
    raise EC2Error(f"Instance {instance_id} not found.")


def _perm_allows_ssh(perm: dict) -> bool:
    """True if an IpPermission entry covers TCP port 22."""
    proto = perm.get("IpProtocol")
    if proto == "-1":
        return True
    if proto in ("tcp", "6"):
        from_port, to_port = perm.get("FromPort"), perm.get("ToPort")
        return from_port is not None and to_port is not None and from_port <= 22 <= to_port
    return False


def check_connectivity(instance_id: str, region: str) -> dict:
    """Report whether an instance is reachable over SSH: does it have a public
    IP, and does one of its security groups allow inbound TCP 22 (and from where)."""
    if region not in VALID_REGIONS:
        raise EC2Error(f"Unsupported region: {region}")
    client = _client(region)
    instance = _find_instance(client, instance_id)

    public_ip = instance.get("PublicIpAddress", "")
    state = instance.get("State", {}).get("Name", "")
    sg_ids = [g["GroupId"] for g in instance.get("SecurityGroups", [])]

    ssh_cidrs = []
    ssh_from_anywhere = False
    if sg_ids:
        try:
            sg_resp = client.describe_security_groups(GroupIds=sg_ids)
        except Exception as e:
            raise _handle_aws_exception(e, "inspect the security groups")
        for sg in sg_resp.get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                if not _perm_allows_ssh(perm):
                    continue
                for rng in perm.get("IpRanges", []):
                    cidr = rng.get("CidrIp")
                    if cidr:
                        ssh_cidrs.append(cidr)
                        if cidr == "0.0.0.0/0":
                            ssh_from_anywhere = True
                for rng in perm.get("Ipv6Ranges", []):
                    if rng.get("CidrIpv6") == "::/0":
                        ssh_from_anywhere = True

    return {
        "instance_id": instance_id,
        "state": state,
        "public_ip": public_ip or "",
        "has_public_ip": bool(public_ip),
        "security_group_ids": sg_ids,
        "ssh_cidrs": sorted(set(ssh_cidrs)),
        "ssh_from_anywhere": ssh_from_anywhere,
    }


def allow_ssh(instance_id: str, region: str, cidr: str = "0.0.0.0/0") -> dict:
    """Add an inbound TCP 22 rule for `cidr` to the instance's primary security
    group. Idempotent: an already-present identical rule is treated as success."""
    if region not in VALID_REGIONS:
        raise EC2Error(f"Unsupported region: {region}")
    if not _CIDR_RE.match(cidr or ""):
        raise EC2Error(f"Invalid CIDR for the SSH rule: {cidr!r}")

    client = _client(region)
    instance = _find_instance(client, instance_id)
    sg_ids = [g["GroupId"] for g in instance.get("SecurityGroups", [])]
    if not sg_ids:
        raise EC2Error("This instance has no security group to modify.")

    target_sg = sg_ids[0]
    try:
        client.authorize_security_group_ingress(
            GroupId=target_sg,
            IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": cidr, "Description": "SSH access via EC2 Manager"}],
            }],
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code != "InvalidPermission.Duplicate":
            raise _handle_aws_exception(e, "open the SSH port")
    except Exception as e:
        raise _handle_aws_exception(e, "open the SSH port")

    return {"security_group_id": target_sg, "cidr": cidr, "port": 22}
