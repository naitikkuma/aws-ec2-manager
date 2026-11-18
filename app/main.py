"""
FastAPI backend for the EC2 Manager dashboard.

Run with:
    uvicorn app.main:app --reload --port 8000

Requires valid AWS credentials configured via one of:
    - ~/.aws/credentials
    - environment variables (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)
    - an attached IAM role (if running on EC2/ECS/etc.)
"""

import secrets
from concurrent.futures import ThreadPoolExecutor

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os

from app import ec2_core as ec2
from app import efs_core as efs


# ==============================================================================
# AUTH (HTTP Basic) — set APP_USERNAME / APP_PASSWORD in the environment.
# Falls back to admin/admin ONLY if unset, so the app still boots for local
# testing — but that fallback prints a loud warning and should never be used
# for anything reachable outside your own machine.
# ==============================================================================

security = HTTPBasic()

APP_USERNAME = os.environ.get("APP_USERNAME", "admin")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "admin")

if "APP_USERNAME" not in os.environ or "APP_PASSWORD" not in os.environ:
    print(
        "WARNING: APP_USERNAME/APP_PASSWORD not set in environment - "
        "using default admin/admin. Set both env vars before deploying anywhere "
        "reachable outside localhost."
    )


def require_auth(credentials: HTTPBasicCredentials = Depends(security)):
    """Global auth gate. Runs before every request. Uses compare_digest to
    avoid leaking timing info that could help brute-force the password."""
    valid_user = secrets.compare_digest(credentials.username, APP_USERNAME)
    valid_pass = secrets.compare_digest(credentials.password, APP_PASSWORD)
    if not (valid_user and valid_pass):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


app = FastAPI(title="EC2 Manager API", dependencies=[Depends(require_auth)])

# Allow the frontend (served separately or via file://) to call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================================================================
# REQUEST / RESPONSE MODELS
# ==============================================================================

class CreateInstanceRequest(BaseModel):
    name: str
    os_type: str          # "amazon-linux" | "ubuntu" | "windows"
    region: str            # "us-east-1" | "us-west-2" | "ap-south-1" | "eu-west-1"
    ami_id: str             # chosen from live /api/amis results
    subnet_id: str          # chosen from live /api/subnets results
    security_group_id: str  # chosen from live /api/security-groups results
    key_name: str            # chosen from live /api/key-pairs results
    instance_type: str = "t3.small"
    enable_efs: bool = True
    reuse_filesystem_id: str = None


class InstanceActionRequest(BaseModel):
    instance_id: str
    region: str


class AllowSshRequest(BaseModel):
    region: str
    cidr: str = "0.0.0.0/0"


# ==============================================================================
# METADATA ENDPOINTS (power the dropdowns/cards in the UI)
# ==============================================================================

@app.get("/api/regions")
def list_regions():
    return [
        {"id": region_id, "label": label}
        for region_id, label in ec2.REGION_LABELS.items()
    ]


@app.get("/api/os-options")
def list_os_options():
    return [
        {"id": os_id, "label": label}
        for os_id, label in ec2.OS_LABELS.items()
    ]


@app.get("/api/amis")
def list_amis(region: str, os_type: str):
    try:
        return {"success": True, "data": ec2.list_amis(region, os_type)}
    except ec2.EC2Error as e:
        raise HTTPException(status_code=400, detail={"message": e.message, "detail": e.detail})


@app.get("/api/subnets")
def list_subnets(region: str):
    try:
        return {"success": True, "data": ec2.list_subnets(region)}
    except ec2.EC2Error as e:
        raise HTTPException(status_code=400, detail={"message": e.message, "detail": e.detail})


@app.get("/api/security-groups")
def list_security_groups(region: str, vpc_id: str = None):
    try:
        return {"success": True, "data": ec2.list_security_groups(region, vpc_id)}
    except ec2.EC2Error as e:
        raise HTTPException(status_code=400, detail={"message": e.message, "detail": e.detail})


@app.get("/api/key-pairs")
def list_key_pairs(region: str):
    try:
        return {"success": True, "data": ec2.list_key_pairs(region)}
    except ec2.EC2Error as e:
        raise HTTPException(status_code=400, detail={"message": e.message, "detail": e.detail})


class CreateKeyPairRequest(BaseModel):
    region: str
    key_name: str
    key_type: str = "rsa"


@app.post("/api/key-pairs")
def create_key_pair(req: CreateKeyPairRequest):
    """Create a new key pair; the response carries the private key so the
    browser can download the .pem (the only chance to obtain it)."""
    try:
        return {"success": True, "data": ec2.create_key_pair(req.region, req.key_name, req.key_type)}
    except ec2.EC2Error as e:
        raise HTTPException(status_code=400, detail={"message": e.message, "detail": e.detail})


# ==============================================================================
# EC2 OPERATIONS
# ==============================================================================

@app.post("/api/instances")
def create_instance(req: CreateInstanceRequest):
    if req.os_type == "windows" and (req.enable_efs or req.reuse_filesystem_id):
        raise HTTPException(
            status_code=400,
            detail={"message": "EFS auto-mount is only supported for Amazon Linux and Ubuntu, not Windows."},
        )

    filesystem_id = None

    try:
        # Step 1: resolve the filesystem (reuse existing orphan, or create new)
        if req.reuse_filesystem_id:
            fs_info = efs.get_filesystem(req.region, req.reuse_filesystem_id)
            filesystem_id = fs_info["filesystem_id"]
        elif req.enable_efs:
            fs_result = efs.create_filesystem(req.region, req.name)
            filesystem_id = fs_result["filesystem_id"]

        # Step 2: create the mount target BEFORE the instance boots. The instance's
        # user-data tries to mount EFS within seconds of boot, so the mount target
        # (the NFS endpoint in the subnet) must already exist and be ready — otherwise
        # the mount silently fails at boot and the instance never sees the EFS data.
        efs_warning = None
        if filesystem_id:
            try:
                vpc_id = ec2._get_vpc_id_for_subnet(ec2._client(req.region), req.subnet_id)
                efs_sg_id = efs.ensure_efs_security_group(req.region, vpc_id, req.security_group_id)
                efs.create_mount_target(req.region, filesystem_id, req.subnet_id, efs_sg_id, req.security_group_id)
                efs.wait_for_mount_target_available(req.region, filesystem_id)
            except ec2.EC2Error as mount_err:
                # Mount target failed — still launch the instance, but skip EFS
                # user-data since there'd be nothing for it to mount.
                efs_warning = mount_err.message
                filesystem_id = None

        # Step 3: build user-data for auto-mount (Linux only)
        user_data = None
        if filesystem_id:
            user_data = efs.build_user_data(filesystem_id, req.region, req.os_type)

        # Step 4: launch the instance
        extra_tags = {"EFSFilesystemId": filesystem_id} if filesystem_id else None
        result = ec2.ec2_create(
            region=req.region,
            os_type=req.os_type,
            name=req.name,
            ami_id=req.ami_id,
            subnet_id=req.subnet_id,
            security_group_id=req.security_group_id,
            key_name=req.key_name,
            instance_type=req.instance_type,
            user_data=user_data,
            extra_tags=extra_tags,
        )

        if filesystem_id:
            efs.tag_filesystem_with_instance(req.region, filesystem_id, result["instance_id"])
            if req.reuse_filesystem_id:
                efs._efs_client(req.region).tag_resource(
                    ResourceId=filesystem_id, Tags=[{"Key": "Status", "Value": "attached"}]
                )
            result["efs_filesystem_id"] = filesystem_id
        if efs_warning:
            result["efs_warning"] = efs_warning

        return {"success": True, "data": result}
    except ec2.EC2Error as e:
        raise HTTPException(status_code=400, detail={"message": e.message, "detail": e.detail})


@app.get("/api/instances")
def list_instances(region: str):
    try:
        result = ec2.ec2_list(region=region)
        return {"success": True, "data": result}
    except ec2.EC2Error as e:
        raise HTTPException(status_code=400, detail={"message": e.message, "detail": e.detail})


def _fan_out_regions(fetch_one):
    """Run `fetch_one(region)` across every valid region in parallel and merge
    the results. Region queries are independent network round-trips, so doing
    them concurrently instead of sequentially cuts the dashboard load time to
    roughly that of a single region."""
    data = []
    errors = []
    regions = list(ec2.VALID_REGIONS)
    with ThreadPoolExecutor(max_workers=len(regions)) as pool:
        results = pool.map(
            lambda region: (region, _safe_fetch(fetch_one, region)), regions
        )
        for region, (rows, err) in results:
            if err is not None:
                errors.append({"region": region, "message": err})
            else:
                data.extend(rows)
    return data, errors


def _safe_fetch(fetch_one, region):
    try:
        return fetch_one(region), None
    except ec2.EC2Error as e:
        return None, e.message


@app.get("/api/instances/all-regions")
def list_instances_all_regions():
    """Aggregate instances across all regions for the dashboard overview."""
    data, errors = _fan_out_regions(lambda region: ec2.ec2_list(region=region))
    return {"success": True, "data": data, "errors": errors}


@app.post("/api/instances/start")
def start_instance(req: InstanceActionRequest):
    try:
        result = ec2.ec2_start(instance_id=req.instance_id, region=req.region)
        return {"success": True, "data": result}
    except ec2.EC2Error as e:
        raise HTTPException(status_code=400, detail={"message": e.message, "detail": e.detail})


@app.post("/api/instances/stop")
def stop_instance(req: InstanceActionRequest):
    try:
        result = ec2.ec2_stop(instance_id=req.instance_id, region=req.region)
        return {"success": True, "data": result}
    except ec2.EC2Error as e:
        raise HTTPException(status_code=400, detail={"message": e.message, "detail": e.detail})


@app.get("/api/instances/{instance_id}/connectivity")
def instance_connectivity(instance_id: str, region: str):
    """Diagnose why SSH might be failing (public IP + port-22 rules)."""
    try:
        return {"success": True, "data": ec2.check_connectivity(instance_id, region)}
    except ec2.EC2Error as e:
        raise HTTPException(status_code=400, detail={"message": e.message, "detail": e.detail})


@app.post("/api/instances/{instance_id}/allow-ssh")
def open_ssh(instance_id: str, req: AllowSshRequest):
    """Add an inbound TCP 22 rule to the instance's security group."""
    try:
        return {"success": True, "data": ec2.allow_ssh(instance_id, req.region, req.cidr)}
    except ec2.EC2Error as e:
        raise HTTPException(status_code=400, detail={"message": e.message, "detail": e.detail})


@app.delete("/api/instances/{instance_id}")
def terminate_instance(instance_id: str, region: str):
    try:
        tags = ec2.get_instance_tags(instance_id, region)
        filesystem_id = tags.get("EFSFilesystemId")

        result = ec2.ec2_terminate(instance_id=instance_id, region=region)

        if filesystem_id:
            try:
                efs.mark_filesystem_orphaned(region, filesystem_id)
                result["efs_filesystem_id"] = filesystem_id
                result["efs_status"] = "orphaned"
            except ec2.EC2Error:
                pass

        return {"success": True, "data": result}
    except ec2.EC2Error as e:
        raise HTTPException(status_code=400, detail={"message": e.message, "detail": e.detail})


@app.get("/api/storage")
def list_storage(region: str):
    try:
        return {"success": True, "data": efs.list_filesystems(region)}
    except ec2.EC2Error as e:
        raise HTTPException(status_code=400, detail={"message": e.message, "detail": e.detail})


@app.get("/api/storage/all-regions")
def list_storage_all_regions():
    data, errors = _fan_out_regions(lambda region: efs.list_filesystems(region))
    return {"success": True, "data": data, "errors": errors}


@app.delete("/api/storage/{filesystem_id}")
def delete_storage(filesystem_id: str, region: str):
    try:
        result = efs.delete_filesystem(region, filesystem_id)
        return {"success": True, "data": result}
    except ec2.EC2Error as e:
        raise HTTPException(status_code=400, detail={"message": e.message, "detail": e.detail})


@app.get("/api/health")
def health():
    return {"status": "ok"}


# ==============================================================================
# SERVE THE FRONTEND (static files) — makes `uvicorn app.main:app` a one-command run
# ==============================================================================

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    def serve_index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
