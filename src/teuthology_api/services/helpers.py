from multiprocessing import Process, Queue
import logging
import os
import uuid
import httpx
from pathlib import Path

from fastapi import HTTPException, Request
from dotenv import load_dotenv

import requests
from requests.exceptions import HTTPError

load_dotenv()

PADDLES_URL = os.getenv("PADDLES_URL")
ARCHIVE_DIR = os.getenv("ARCHIVE_DIR")
TEUTHOLOGY_PATH = os.getenv("TEUTHOLOGY_PATH")

ADMIN_TEAM = os.getenv("ADMIN_TEAM")
GH_ORG_TEAM_URL = os.getenv("GH_ORG_TEAM_URL")
GH_FETCH_MEMBERSHIP_URL = os.getenv("GH_FETCH_MEMBERSHIP_URL")
GH_USER_URL = "https://api.github.com/user"

log = logging.getLogger(__name__)


def logs_run(func, args):
    """
    Run the command function in a seperate process (to isolate logs),
    and return logs printed during the execution of the function.
    """
    _id = str(uuid.uuid4())
    archive = Path(ARCHIVE_DIR)
    log_file = archive / f"{_id}.log"
    teuth_queue = Queue()
    teuth_process = Process(
        target=_execute_with_logs, args=(func, args, log_file, teuth_queue)
    )
    teuth_process.daemon = True
    teuth_process.start()
    teuth_process.join(timeout=180)
    if teuth_process.is_alive():
        teuth_process.terminate()
        teuth_process.join()
        raise TimeoutError("Process execution timed out")
    logs = ""
    with open(log_file, encoding="utf-8") as file:
        logs = file.readlines()
    if os.path.isfile(log_file):
        os.remove(log_file)
    if teuth_process.exitcode > 0:
        e = teuth_queue.get()
        log.error(e)
        return "fail", e, 0
    job_count = teuth_queue.get()
    return "success", logs, job_count


def _execute_with_logs(func, args, log_file, teuth_queue):
    """
    To store logs, set a new FileHandler for teuthology root logger
    and then execute the command function.
    Teuthology is imported here (in the subprocess only) to avoid gevent
    monkey-patching in the main API workers, which conflicts with asyncio/anyio.
    We force gevent to skip patching ssl to avoid RecursionError when
    teuthology/requests hit HTTPS (e.g. shaman.ceph.com).
    """
    # Teuthology/paddles often use getpass.getuser() or os.environ["USER"] for
    # the run owner; set env so the run is created under the authenticated user.
    run_user = args.get("--user")
    if run_user:
        os.environ["USER"] = str(run_user)
        os.environ["LOGNAME"] = str(run_user)
    import gevent.monkey  # noqa: E402 - before teuthology
    _orig_patch_all = gevent.monkey.patch_all

    def _patch_all_ssl_off(**kwargs):
        kwargs["ssl"] = False
        return _orig_patch_all(**kwargs)

    gevent.monkey.patch_all = _patch_all_ssl_off
    import yaml  # noqa: E402
    import teuthology  # noqa: E402 - defer to avoid gevent in API workers
    teuthology.setup_log_file(log_file)
    # Apply <config_yaml> overrides to teuthology's global config. Teuthology
    # normally loads only from ~/.teuthology.yaml / TEUTHOLOGY_CONFIG; it uses
    # <config_yaml> only for job YAML. So we merge override files into the
    # global config here so options like teuthology_path/teuthology_git_url apply.
    config_yaml_paths = args.get("<config_yaml>") or []
    if config_yaml_paths:
        from teuthology.config import config as teuth_config  # noqa: E402
        for path in config_yaml_paths:
            path = os.path.abspath(os.path.expanduser(str(path)))
            if os.path.isfile(path):
                try:
                    with open(path, encoding="utf-8") as f:
                        override = yaml.safe_load(f)
                    if override and isinstance(override, dict):
                        teuth_config.update(override)
                        log.debug("Applied config override from %s", path)
                except Exception as e:
                    log.warning("Could not load config override %s: %s", path, e)
                break
    # Resolve func by name if passed as string (e.g. "teuthology.suite.main")
    if isinstance(func, str):
        import importlib
        mod_path, _, attr = func.rpartition(".")
        mod = importlib.import_module(mod_path)
        func = getattr(mod, attr)
    try:
        job_count = func(args)
        teuth_queue.put(job_count)
    except Exception as e:
        teuth_queue.put(e)
        raise


def get_run_details(run_name: str):
    """
    Queries paddles to look if run is created.
    """
    url = f"{PADDLES_URL}/runs/{run_name}/"
    try:
        run_info = requests.get(url)
        run_info.raise_for_status()
        return run_info.json()
    except HTTPError as http_err:
        log.error(http_err)
        raise HTTPException(
            status_code=http_err.response.status_code, detail=str(http_err)
        ) from http_err
    except Exception as err:
        log.error(err)
        raise HTTPException(status_code=500, detail=str(err)) from err


async def _validate_token_with_github(token: str):
    """
    Validate a GitHub access token and return (username, token_dict).
    Checks token validity and Ceph org membership.
    """
    if not GH_FETCH_MEMBERSHIP_URL:
        raise HTTPException(
            status_code=500,
            detail="GH_FETCH_MEMBERSHIP_URL is not configured",
        )
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": "token " + token, "Accept": "application/json"}
        user_resp = await client.get(url=GH_USER_URL, headers=headers)
        if user_resp.status_code != 200:
            log.error("Token validation failed: %s", user_resp.text)
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user_data = user_resp.json()
        username = user_data.get("login")
        if not username:
            raise HTTPException(
                status_code=401,
                detail="Could not get username from token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Verify Ceph org membership
        membership_resp = await client.get(
            url=GH_FETCH_MEMBERSHIP_URL, headers=headers
        )
        if membership_resp.status_code == 404:
            log.error("User %s is not part of the Ceph Organization", username)
            raise HTTPException(
                status_code=403,
                detail="User is not part of the Ceph Organization",
            )
        if membership_resp.status_code != 200:
            log.error("Membership check failed: %s", membership_resp.text)
            raise HTTPException(
                status_code=401,
                detail="Failed to verify organization membership",
                headers={"WWW-Authenticate": "Bearer"},
            )
    return username, {"access_token": token, "token_type": "bearer"}


async def resolve_access_token(request: Request, direct_token: str = None):
    """
    Resolve access token from multiple sources (in order of precedence):
    1. Direct token parameter (X-Access-Token header for headless auth)
    2. Authorization: Bearer header
    3. Session cookie (browser login)

    Returns (username, token_dict). Validates tokens against GitHub.
    """
    # 1. Check for direct token (X-Access-Token header)
    if direct_token is not None:
        token = (direct_token or "").strip()
        if token:
            log.info("Using X-Access-Token header for auth")
            username, token_dict = await _validate_token_with_github(token)
            log.info("Resolved username from token: %s", username)
            return username, token_dict

    # 2. Check for Bearer token (Authorization header)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if token:
            log.info("Using Authorization: Bearer for auth")
            username, token_dict = await _validate_token_with_github(token)
            log.info("Resolved username from token: %s", username)
            return username, token_dict

    # 3. Fall back to session (browser login)
    user = request.session.get("user", {}) or {}
    username = user.get("username")
    token = user.get("access_token")
    if username and token:
        log.info("Using session for auth; username: %s", username)
        return username, {"access_token": token, "token_type": "bearer"}

    log.error("No valid auth: missing session, Bearer token, or X-Access-Token.")
    raise HTTPException(
        status_code=401,
        detail="You need to be logged in. Use X-Access-Token header, Authorization: Bearer header, or browser login.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def _resolve_auth(request: Request):
    """
    Resolve auth from session or Authorization: Bearer header.
    Returns (username, token_dict). Validates Bearer tokens against GitHub.
    
    Deprecated: Use resolve_access_token() instead for new code.
    """
    return await resolve_access_token(request)


async def get_username(request: Request):
    """
    Get username from session or Authorization: Bearer header.
    """
    username, _ = await _resolve_auth(request)
    return username


async def get_token(request: Request):
    """
    Get access token from session or Authorization: Bearer header.
    """
    _, token_dict = await _resolve_auth(request)
    return token_dict


async def isAdmin(username, token):
    if not (GH_ORG_TEAM_URL and ADMIN_TEAM):
        log.error("GH_ORG_TEAM_URL or ADMIN_TEAM is not set in .env")
        return False
    if not (token and username):
        raise HTTPException(
            status_code=401,
            detail="You are probably not logged in (username or token missing)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    TEAM_MEMBER_URL = f"{GH_ORG_TEAM_URL}/{ADMIN_TEAM}/memberships/{username}"
    async with httpx.AsyncClient() as client:
        headers = {
            "Authorization": "token " + token,
            "Accept": "application/json",
        }
        response_org = await client.get(url=TEAM_MEMBER_URL, headers=headers)
        if response_org:
            response_org_dict = dict(response_org.json())
            if response_org_dict.get("state", "") == "active":
                return True
        return False
