"""
AWS EFS Core Logic Library

Design: one EFS filesystem per EC2 instance, created automatically at launch.
- The filesystem is tagged with the instance name/id so it can be traced back
  even after the instance is terminated (EFS is NEVER auto-deleted by this app).
- A mount target is created in the same subnet as the instance, protected by a
  dedicated "EFS access" security group that only allows NFS (port 2049) from
  the instance's own security group.
- The instance mounts it automatically at /mnt/data via a user-data script
  using amazon-efs-utils (works on Amazon Linux and Ubuntu; Windows is not
  supported by this flow — EFS mount helper is Linux-only).
"""

import time
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError

from app.ec2_core import EC2Error, _handle_aws_exception, VALID_REGIONS, _get_client


def _efs_client(region: str):
    return _get_client("efs", region)


def _ec2_client(region: str):
    return _get_client("ec2", region)


# ==============================================================================
# SECURITY GROUP FOR EFS (NFS on 2049)
# ==============================================================================

def ensure_efs_security_group(region: str, vpc_id: str, instance_sg_id: str) -> str:
    """
    Finds or creates a security group that allows inbound NFS (2049) from the
    instance's own security group. Returns the EFS SG id.
    """
    ec2 = _ec2_client(region)
    sg_name = "efs-access-sg-auto"

    try:
        existing = ec2.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": [sg_name]},
                {"Name": "vpc-id", "Values": [vpc_id]},
            ]
        )
        if existing["SecurityGroups"]:
            return existing["SecurityGroups"][0]["GroupId"]

        created = ec2.create_security_group(
            GroupName=sg_name,
            Description="Auto-created: allows NFS (2049) inbound for EFS mount targets",
            VpcId=vpc_id,
            TagSpecifications=[{
                "ResourceType": "security-group",
                "Tags": [{"Key": "Name", "Value": sg_name}, {"Key": "ManagedBy", "Value": "ec2-manager"}],
            }],
        )
        sg_id = created["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 2049,
                "ToPort": 2049,
                "UserIdGroupPairs": [{"GroupId": instance_sg_id}],
            }],
        )
        return sg_id
    except Exception as e:
        raise _handle_aws_exception(e, "prepare the EFS security group")


# ==============================================================================
# EFS FILESYSTEM OPERATIONS
# ==============================================================================

def create_filesystem(region: str, instance_name: str) -> dict:
    """Creates a new EFS filesystem tagged with the origin instance name."""
    efs = _efs_client(region)
    try:
        response = efs.create_file_system(
            PerformanceMode="generalPurpose",
            ThroughputMode="bursting",
            Encrypted=True,
            Tags=[
                {"Key": "Name", "Value": f"efs-{instance_name}"},
                {"Key": "OriginInstanceName", "Value": instance_name},
                {"Key": "ManagedBy", "Value": "ec2-manager"},
                {"Key": "Status", "Value": "attached"},
            ],
        )
        fs_id = response["FileSystemId"]

        # Wait for the filesystem to become available before creating mount targets
        waiter_tries = 0
        while waiter_tries < 15:
            desc = efs.describe_file_systems(FileSystemId=fs_id)
            if desc["FileSystems"][0]["LifeCycleState"] == "available":
                break
            time.sleep(2)
            waiter_tries += 1

        return {"filesystem_id": fs_id}
    except Exception as e:
        raise _handle_aws_exception(e, "create the EFS filesystem")


def create_mount_target(region: str, filesystem_id: str, subnet_id: str, security_group_id: str, instance_security_group_id: str = None) -> dict:
    efs = _efs_client(region)
    ec2 = _ec2_client(region)
    try:
        response = efs.create_mount_target(
            FileSystemId=filesystem_id,
            SubnetId=subnet_id,
            SecurityGroups=[security_group_id],
        )
        if instance_security_group_id:
            try:
                ec2.authorize_security_group_ingress(
                    GroupId=security_group_id,
                    IpPermissions=[{
                        "IpProtocol": "tcp",
                        "FromPort": 2049,
                        "ToPort": 2049,
                        "UserIdGroupPairs": [{"GroupId": instance_security_group_id}],
                    }],
                )
            except ClientError as auth_err:
                if auth_err.response.get("Error", {}).get("Code") != "InvalidPermission.Duplicate":
                    raise _handle_aws_exception(auth_err, "authorize EFS access for the new instance")
        return {"mount_target_id": response["MountTargetId"], "ip_address": response.get("IpAddress")}
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code != "MountTargetConflict":
            raise _handle_aws_exception(e, "create the EFS mount target")

        # EFS allows only one mount target per AZ per filesystem. This fires
        # when a mount target already exists in the AZ of the chosen subnet
        # (e.g. reusing an existing filesystem, or a second instance landing
        # in the same AZ). The instance can still mount fine — just reuse the
        # existing mount target instead of treating this as a failure.
        try:
            target_az = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["AvailabilityZone"]
            existing_targets = efs.describe_mount_targets(FileSystemId=filesystem_id)["MountTargets"]
            for mt in existing_targets:
                mt_az = ec2.describe_subnets(SubnetIds=[mt["SubnetId"]])["Subnets"][0]["AvailabilityZone"]
                if mt_az == target_az:
                    # The mount target's attached SG (security_group_id, i.e.
                    # efs-access-sg-auto) is almost always already correct here —
                    # what actually blocks NEW instances is that the EFS SG's
                    # inbound 2049 rule only authorizes the OLD instance's SG as
                    # a source. Authorize the new instance's SG too so traffic
                    # from it isn't silently dropped.
                    if instance_security_group_id:
                        try:
                            ec2.authorize_security_group_ingress(
                                GroupId=security_group_id,
                                IpPermissions=[{
                                    "IpProtocol": "tcp",
                                    "FromPort": 2049,
                                    "ToPort": 2049,
                                    "UserIdGroupPairs": [{"GroupId": instance_security_group_id}],
                                }],
                            )
                        except ClientError as auth_err:
                            # Duplicate rule is fine (already authorized); anything else, surface it.
                            if auth_err.response.get("Error", {}).get("Code") != "InvalidPermission.Duplicate":
                                raise _handle_aws_exception(auth_err, "authorize EFS access for the new instance")
                    return {
                        "mount_target_id": mt["MountTargetId"],
                        "ip_address": mt.get("IpAddress"),
                        "reused_existing": True,
                    }
        except ClientError:
            raise
        except Exception:
            pass
        # Couldn't resolve to an existing target in the same AZ — surface the original error
        raise _handle_aws_exception(e, "create the EFS mount target")


def wait_for_mount_target_available(region: str, filesystem_id: str, max_tries: int = 15):
    """
    Blocks until at least one mount target for this filesystem reaches
    'available' state. A freshly-created mount target starts in 'creating'
    and typically takes a few seconds to become reachable over NFS. If the
    instance boots and tries to mount before this happens, the mount fails
    silently and the instance never sees the EFS data — so this must be
    called (and awaited) before launching the instance.
    """
    efs = _efs_client(region)
    try:
        for _ in range(max_tries):
            targets = efs.describe_mount_targets(FileSystemId=filesystem_id)["MountTargets"]
            if any(mt["LifeCycleState"] == "available" for mt in targets):
                return
            time.sleep(2)
    except Exception as e:
        raise _handle_aws_exception(e, "wait for the EFS mount target to become available")


def tag_filesystem_with_instance(region: str, filesystem_id: str, instance_id: str):
    """After the instance exists, stamp its ID onto the EFS for cross-reference."""
    efs = _efs_client(region)
    try:
        efs.tag_resource(
            ResourceId=filesystem_id,
            Tags=[{"Key": "OriginInstanceId", "Value": instance_id}],
        )
    except Exception as e:
        # Non-fatal — tagging failure shouldn't block instance creation
        pass


def mark_filesystem_orphaned(region: str, filesystem_id: str):
    """Called when the owning instance is terminated. EFS itself is untouched."""
    efs = _efs_client(region)
    try:
        efs.tag_resource(
            ResourceId=filesystem_id,
            Tags=[{"Key": "Status", "Value": "orphaned"}],
        )
    except Exception as e:
        raise _handle_aws_exception(e, "mark the filesystem as orphaned")


def list_filesystems(region: str) -> list:
    """Lists all EFS filesystems created by this app (tagged ManagedBy=ec2-manager)."""
    efs = _efs_client(region)
    try:
        response = efs.describe_file_systems()
    except Exception as e:
        raise _handle_aws_exception(e, "list EFS filesystems")

    results = []
    for fs in response.get("FileSystems", []):
        tags = {t["Key"]: t["Value"] for t in fs.get("Tags", [])}
        if tags.get("ManagedBy") != "ec2-manager":
            continue
        results.append({
            "filesystem_id": fs["FileSystemId"],
            "name": tags.get("Name", fs["FileSystemId"]),
            "origin_instance_name": tags.get("OriginInstanceName", "unknown"),
            "origin_instance_id": tags.get("OriginInstanceId", ""),
            "status": tags.get("Status", "unknown"),  # "attached" | "orphaned"
            "lifecycle_state": fs.get("LifeCycleState"),
            "size_bytes": fs.get("SizeInBytes", {}).get("Value", 0),
            "region": region,
            "created": fs.get("CreationTime").isoformat() if fs.get("CreationTime") else None,
        })
    return results


def get_filesystem(region: str, filesystem_id: str) -> dict:
    efs = _efs_client(region)
    try:
        response = efs.describe_file_systems(FileSystemId=filesystem_id)
    except Exception as e:
        raise _handle_aws_exception(e, "look up the EFS filesystem")
    if not response["FileSystems"]:
        raise EC2Error(f"Filesystem {filesystem_id} not found in {region}")
    fs = response["FileSystems"][0]
    tags = {t["Key"]: t["Value"] for t in fs.get("Tags", [])}
    return {
        "filesystem_id": fs["FileSystemId"],
        "status": tags.get("Status", "unknown"),
        "lifecycle_state": fs.get("LifeCycleState"),
    }


def delete_filesystem(region: str, filesystem_id: str):
    """
    Permanently deletes an EFS filesystem and its mount targets.
    This is a deliberate, separate action from instance termination —
    the whole point of this feature is that termination does NOT do this.
    """
    efs = _efs_client(region)
    try:
        mt_response = efs.describe_mount_targets(FileSystemId=filesystem_id)
        for mt in mt_response.get("MountTargets", []):
            efs.delete_mount_target(MountTargetId=mt["MountTargetId"])

        # Mount target deletion is async; wait briefly before deleting the FS
        for _ in range(15):
            remaining = efs.describe_mount_targets(FileSystemId=filesystem_id)
            if not remaining.get("MountTargets"):
                break
            time.sleep(2)

        efs.delete_file_system(FileSystemId=filesystem_id)
        return {"filesystem_id": filesystem_id, "status": "deleted"}
    except Exception as e:
        raise _handle_aws_exception(e, "delete the EFS filesystem")


# ==============================================================================
# USER-DATA SCRIPT (auto-mount on boot)
# ==============================================================================

def build_user_data(filesystem_id: str, region: str, os_type: str, mount_path: str = "/mnt/data") -> str:
    """
    Returns a cloud-init/bash user-data script that installs amazon-efs-utils
    and mounts the given EFS filesystem at boot, persisted via /etc/fstab so
    it survives reboots. Linux only (amazon-linux / ubuntu) — Windows EC2
    instances don't support the EFS mount helper the same way and are skipped.
    """
    if os_type == "amazon-linux":
        installer = "yum install -y amazon-efs-utils"
    elif os_type == "ubuntu":
        installer = (
            "apt-get update -y && "
            "apt-get install -y git binutils rustc cargo pkg-config libssl-dev && "
            "git clone https://github.com/aws/efs-utils /opt/efs-utils && "
            "cd /opt/efs-utils && ./build-deb.sh && "
            "apt-get install -y ./build/amazon-efs-utils*deb"
        )
    else:
        # Windows or unsupported OS — no auto-mount script
        return ""

    script = f"""#!/bin/bash
set -e
{installer}
mkdir -p {mount_path}
# NOTE: no 'iam' mount option here — this app authorizes EFS access via
# security groups (efs-access-sg-auto), not IAM instance profiles. Launched
# instances don't get an IAM role attached, so 'tls,iam' would always fail
# authentication even when the network path is perfectly fine.
echo "{filesystem_id}:/ {mount_path} efs _netdev,tls 0 0" >> /etc/fstab

# Retry the mount for up to ~2 minutes. Even once the mount target is
# "available", DNS propagation can take a few extra seconds, and a failed
# `mount -a` does not exit non-zero, so we verify by checking whether the
# path is actually mounted rather than trusting the exit code.
for i in $(seq 1 24); do
    mount -a -t efs 2>/dev/null || true
    if mountpoint -q {mount_path}; then
        chmod 777 {mount_path}
        break
    fi
    sleep 5
done

if ! mountpoint -q {mount_path}; then
    mount -t efs -o tls {filesystem_id}:/ {mount_path} || true
fi

# Safety net in case the mount landed via the fallback line above rather
# than inside the loop — chmod only ever targets a confirmed live mount.
if mountpoint -q {mount_path}; then
    chmod 777 {mount_path}
fi
"""
    return script
