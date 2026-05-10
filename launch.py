"""
`launch.py`

The single entry point for the logic flaw scanner. Handles the DOcker container setup, the target account creation, interactive scan config,
and scanner invocation.
"""

import os
import subprocess
import sys
import time

import requests


# Colours for the terminal output. Defines the ANSDI escape codes, as class attributes so they can be referenced inline in f-strings.
class C:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    # Resets all fromatting so the colour doesnt bleed into the next printed line.
    RESET = "\033[0m"


# Shorthanded print helpers keyed by severity, and used throughout the launch sequence.
def ok(msg):
    print(f"{C.GREEN}[+]{C.RESET} {msg}")


def info(msg):
    print(f"{C.CYAN}[*]{C.RESET} {msg}")


def warn(msg):
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def err(msg):
    print(f"{C.RED}[x]{C.RESET} {msg}")


def banner(msg):
    print(f"\n{C.BOLD}{C.CYAN}{msg}{C.RESET}")


# Docker helpers.
def _docker_run(args, capture=False):
    """Runs a docker command, returning stdout string, or None on failure.

    Args:
        args (list[str]): The docker subcommand, and its arguments e.g., `['inspect', '-f', '{{.State.Running}}', 'juice-shop']`.

        capture (bool): If `True`. returns the stripped stdout string from the command. If `False`, returns a bool indicating
        whether the exit code was 0. Defaults to `False`.

    Returns:
        str or bool or None: THe stripped stdout string, when `capture` is True, or a bool when `capture` is `False`. Reutrns `None`
        on exceptioon when `capture` is `True`, and `False` on exception when `capture` is `False`."""

    try:
        # Passes the docker subcommand list, directly to subprocess to avoid shell injection risks.
        r = subprocess.run(
            ["docker"] + args, capture_output=True, text=True, timeout=60
        )

        # Returns the stripped stdout string, when the caller needs the output value, e.g., inspect queries.
        if capture:
            return r.stdout.strip()
        # Returns a simple bool for when the caller onlyt needs to know whether the command succeeded.
        return r.returncode == 0

    except Exception as e:
        warn(f"docker command failed: {e}")
        # Returns a type-consistent fallback, so tht callers dont need to handle NOne vs False separately.
        return None if capture else False


def _container_running(name):
    """Checks whether the named DOcker container is currently running by querying its live state, via `docker inspect`.

    Args:
        name (str): The docker container name to inspect, e.g., `'juice-shop'`.

        Returns:
            bool: `True`, if the container exists, and its running state is `true`. `False` if it is stopped, paused, or doesnt exist."""

    #   Queries the containers live running state, using Dockers GO template format.
    out = _docker_run(["inspect", "-f", "{{.State.Running}}", name], capture=True)
    # Docker returns the literal string "true", rather than a boolean.
    return out == "true"


def _container_exists(name):
    """Checks whether a Docker container, with the given name, exists on this host, regardless of whether it is running or stopped.

    Args:
        name (str): The docker container name to check, e.g., `dvwa`.

    Returns:
        bool: `True`, if no container by this name exists, `False`, if `docker inspect` returns a non-zero exit code indicating no such container."""

    # Uses inspect with no format string, a non-zero exit code means that the container doent exist yet.
    r = subprocess.run(["docker", "inspect", name], capture_output=True, text=True)
    return r.returncode == 0


def ensure_container(name, image, port_mapping):
    """Ensures that the named container is running, starting, or creating if necessary. Tries 3 paths in order: already runbning, exists-but-stopped,
    and create from image.

    Args:
        name (str): The docker container name e.g., `juice-shop`.

        image (str): The Docker image tag to use if the container must be created, e.g., `'bkimminich/juice-shop:v17.1.1'`.

        port-mapping (str): The host-to-container port mapping string, passed to `docker run -p`, e.g., `'3000:3000'`.

    Returns:
        bool: `True` if the container is running after this call, `False` if any docker command failed, and the container could not be started."""

    # SKips all setup work immediately, if the container is already running.
    if _container_running(name):
        ok(f"{name} already running.")
        return True
    # Starts an existing, but stopped container, rather than creating a duplicate.
    if _container_exists(name):
        info(f"Starting existing {name} container...")
        return _docker_run(["start", name])
    # Falls through to creation, only when no container by this name exists at all.
    info(f"Creating {name} container from {image}...")
    return _docker_run(["run", "-d", "--name", name, "-p", port_mapping, image])


def wait_for_http(url, label, timeout=120):
    """Polls `url` with GET requests ever 3 seconds, until a 200 response is returned, or the `timeout` deadline is reached.

    Args"
        url (str): The absolute URL to poll e.g., `http://localhost:3000`

        label (str): HUman-readable target name used in log output, e.g., `Juice Shop`.

        timeout (int): The maximum number of seconds to wait before giving up. Defualts to 120.

    Returns:
        bool: `True`, if a 200 response was received prior to deadline, `False` if the timeout expired without a successful response."""

    info(f"Waiting for {label} to be ready at {url} ...")
    # Records the absolute deadline, rather than counting down a loop iteration counter.
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=5)
            # A 200 response confirms the app has finish booting, and is serving requests.
            if r.status_code == 200:
                ok(f"{label} is up.")
                return True
        except Exception:
            # Silently swallows connection errors during boot, they are expected until the app is ready.
            pass
        # Waits 3 seconds between polls, to avoid spamming the container whilst it boots.
        time.sleep(3)
    err(f"{label} did not become ready within {timeout}s.")
    return False


def wait_for_dvwa_mysql(timeout=90):
    """Pollst he MYSQL instance inside the `dvwa` container, every 3 seconds, until the database is accessible, or the `timeout` deadline is reached.

    Args:
        timeout (int): Maximum number of seconds to wait before giving up. Defaults to 90.

    Returns:
        bool: `True` if `USE dvwa` executed successfully inside the container, `False` if the timeout expired before MYSQL became reachable."""

    info("Waiting for DVWA MySQL to be ready...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        # RUns a trivial USE statement, inside the container, to confirm MYSQL is accepting connections.
        r = subprocess.run(
            [
                "docker",
                "exec",
                "dvwa",
                "mysql",
                "-u",
                "root",
                "-pvulnerables",
                "-e",
                "USE dvwa;",
            ],
            capture_output=True,
            text=True,
        )
        # Exit code 0 means taht MYSQL accepted the connection, and the dvwa database exists.
        if r.returncode == 0:
            ok("DVWA MySQL is ready.")
            return True
        time.sleep(3)
    err("DVWA MySQL did not become ready in time.")
    return False


# ── Configuration state check ─────────────────────────────────────────────────


def _check_configured():
    """Verifies that both containers are running, the Juice Shop admin account is
    accessible with the known password, and `user_a` exists in the DVWA database.
    Used at startup to decide whether to skip the setup phases.

    Returns:
        bool: `True` if all 3 checks pass and setup can be skipped, `False` if any
            check fails and the full setup sequence must run.
    """
    # Both containers must be running before any HTTP or MySQL check is worth attempting.
    if not _container_running("juice-shop") or not _container_running("dvwa"):
        return False

    # Confirms the Juice Shop admin account exists with the expected password.
    try:
        r = requests.post(
            "http://localhost:3000/rest/user/login",
            json={"email": "admin@juice-sh.op", "password": "CHANGE_ME_ADMIN"},
            timeout=5,
        )
        if "authentication" not in r.json():
            return False
    except Exception:
        # Any network failure here means Juice Shop is not yet ready.
        return False

    # Confirms user_a was previously inserted into the DVWA users table.
    result = subprocess.run(
        [
            "docker",
            "exec",
            "dvwa",
            "mysql",
            "-u",
            "root",
            "-pvulnerables",
            "dvwa",
            "-e",
            "SELECT user FROM users WHERE user='user_a';",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or "user_a" not in result.stdout:
        return False

    return True


# JS account setup.


def setup_juice_shop_accounts():
    """Creates, or resets, the admin, user_a, user_b accounts on the JS instance at `http://localhost:3000`. Uses the SQLi bvypass,
    to obtaiun an initial admin JWT, resets the admin password, registers both test users, then verifies all 3 logins.

    Returns:
        bool: `True`, if at least 2 of the 3 account logins were verified successfully, `False` if the initial admin token could not be obtained."""

    base = "http://localhost:3000"
    info("Setting up Juice Shop accounts...")

    # Uses the JS SQLi bypass to obtain an admin JWT, without knowing the password.
    try:
        r = requests.post(
            f"{base}/rest/user/login",
            json={"email": "' OR 1=1--", "password": "anything"},
            timeout=10,
        )
        # Extracts the token, from the nested authentication object returned by JS.
        token = r.json()["authentication"]["token"]
    except Exception as e:
        err(f"Could not get admin token: {e}")
        return False

    # Sets a known admin password, so the YAML config credentials remainn valid on every run.
    try:
        requests.get(
            f"{base}/rest/user/change-password",
            params={"current": "", "new": "CHANGE_ME_ADMIN", "repeat": "CHANGE_ME_ADMIN"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
    except Exception as e:
        # Warns rather than failing here, as the password may have been set correctly on a previous run.
        warn(f"Admin password change failed (may already be set): {e}")

    # Iterates over both test accounts, and registers them via the publikc API endpoint.
    for email, password, answer in [
        ("user_a@test.com", "CHANGE_ME_USER_A", "Vlad"),
        ("user_b@test.com", "CHANGE_ME_USER_B", "Tepesh"),
    ]:
        try:
            # Registers each user with security question answer, which JS requires on account creation.
            requests.post(
                f"{base}/api/Users",
                json={
                    "email": email,
                    "password": password,
                    "passwordRepeat": password,
                    "securityQuestion": {"id": 1},
                    "securityAnswer": answer,
                },
                timeout=10,
            )
        except Exception as e:
            warn(f"Could not create {email}: {e}")

    # Verifies all 3 accounts, by performing a real login, and checking for the authentication key.
    ok_count = 0
    for email, password, label in [
        ("admin@juice-sh.op", "CHANGE_ME_ADMIN", "admin"),
        ("user_a@test.com", "CHANGE_ME_USER_A", "user_a"),
        ("user_b@test.com", "CHANGE_ME_USER_B", "user_b"),
    ]:
        try:
            r = requests.post(
                f"{base}/rest/user/login",
                json={"email": email, "password": password},
                timeout=10,
            )
            # Presence of the authentication key confirms that the login was actualyl accepted.
            if "authentication" in r.json():
                ok(f"  {label}: login verified")
                ok_count += 1
            else:
                warn(f"  {label}: login failed")
        except Exception as e:
            warn(f"  {label}: verification error - {e}")

    # Requires at least 2 of 3 accounts to verify, admin failing alone shouldnt abort setup.
    return ok_count >= 2


# DVWA account setup.


def setup_dvwa_accounts():
    """Inserts `user_a`, and `user_b` into the DVWA MySQL databse, using `docker exec`. Uses `INSERT IGNORE` so that the call is safe
    to repeat on every run, without fialing on duplicate rows.

    Returns:
        bool: Always returns `True`. A non-zero exit code from MySQL is treated as a harmless duplicate, rather than a hard failure, and
        a warning is logged."""

    info("Setting up DVWA test accounts...")
    # Uses INSET IGNORE, so that repeated runs dont fail on duplicate user_id, or username values.
    sql = """
    INSERT IGNORE INTO users
        (user_id, first_name, last_name, user, password, avatar, last_login, failed_login)
    VALUES
        (6,'Test','UserA','user_a',MD5('CHANGE_ME_USER_A'),'/hackable/users/user_a.jpg',NOW(),0),
        (7,'Test','UserB','user_b',MD5('CHANGE_ME_USER_B'),'/hackable/users/user_b.jpg',NOW(),0);
    """
    # Executes the INSERT directly inside the running dvwa container, via docker exec.
    r = subprocess.run(
        [
            "docker",
            "exec",
            "dvwa",
            "mysql",
            "-u",
            "root",
            "-pvulnerables",
            "dvwa",
            "-e",
            sql,
        ],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        ok("DVWA accounts inserted.")
        return True
    # Non-zero exit here is almost always a harmless duplicate, and INSERT IGNORE handles it.
    warn(
        f"DVWA account insert returned non-zero (may already exist): {r.stderr.strip()}"
    )
    return True


# Interactive menu. Maps menu number strings to (scanner_token, display_description) pairs.
MODULES = {
    "1": ("crawl", "Crawler           - discover endpoints"),
    "2": ("params", "Parameters        - enumerate & fuzz params"),
    "3": ("unauth", "Unauth access     - unauthenticated bypass"),
    "4": ("session", "Session           - termination & fixation"),
    "5": ("idor", "IDOR / BOLA       - horizontal auth"),
    "6": ("vertical", "Vertical auth     - privilege escalation"),
    "7": ("workflow", "Workflow bypass   - multi-step logic flaws"),
    "8": ("ratelimit", "Rate limiting     - detection & bypass"),
}


def pick_target():
    """Prompts the user to select a scan tareget from JS, DVWA, or both, and returns a list of `(namne, config_path)` tuples, for use by `run_scan`.

    Returns:
        list[tuple[str, str]]: A list of 1, or 2 tuples, each containing the tareget short nme e.g., `juiceshop`, and its YAML config path e.g.,
        `configs/juiceshop.yaml`. Both targets are returned in JS-first order, when option 3 is selected."""

    banner("─── Select Scan Target ───────────────────────────────")
    print("  1)  OWASP Juice Shop  (http://localhost:3000)")
    print("  2)  DVWA              (http://localhost:8080)")
    print("  3)  Both")
    # Loops until the user enters a valid choice, rejecting anything else with a warning.
    while True:
        choice = input(f"\n{C.BOLD}Target [1/2/3]: {C.RESET}").strip()
        # Returns a list of (name, config_path) tuples, so that `run_scan` can iterate the same way.
        if choice == "1":
            return [("juiceshop", "configs/juiceshop.yaml")]
        if choice == "2":
            return [("dvwa", "configs/dvwa.yaml")]
        if choice == "3":
            # Both targets are returned in JS-first order, matching the setup verification order.
            return [
                ("juiceshop", "configs/juiceshop.yaml"),
                ("dvwa", "configs/dvwa.yaml"),
            ]

        warn("Please enter 1, 2, or 3.")


def pick_scan_type():
    """Prompts the user to choose between a full scan, and a custom module selection, then returns the appropriate module string for ``--modules`.

    Returns:
        str: Either the sentinel string `all` for a full scan, or a comma-separated module token string e.g., `crawl,idor,ratelimit`, as returned by
        `pick_modules`."""

    banner("─── Select Scan Type ─────────────────────────────────")
    print("  1)  Full scan  (all modules)")
    print("  2)  Select modules")
    while True:
        choice = input(f"\n{C.BOLD}Scan type [1/2]: {C.RESET}").strip()
        if choice == "1":
            # Returns the sntinel string "all", which `main.py` passes directly to `--modules`.
            return "all"
        if choice == "2":
            # Delegates to the module checklist picker, and returns its comma-separaed result.
            return pick_modules()
        warn("Please enter 1 or 2.")


def pick_modules():
    """Presents the numbered modulke list, and prompts the user to enter a space-separated selection. Validates each entry, auto-prepends `crawl`
    if missing, and returns a comma-separated token string.

    Returns:
        str: A comma-separated string of module tokens ready to pass `--modules`, e.g., `crawl,idor,vertical`. `crawl` is always included at the
        first token, since all the test modules depend on its output."""

    banner("─── Select Modules ───────────────────────────────────")
    print("  Enter the numbers of the modules you want to run,")
    print("  separated by spaces (e.g., 1 3 5 8).\n")
    # Prints the full module list, so that the user can see descriptions before choosing.,
    for key, (token, desc) in MODULES.items():
        print(f"  {key})  {desc}")

    while True:
        raw = input(f"\n{C.BOLD}Modules: {C.RESET}").strip()
        # Splits on whitespace, so that both "1 3 5", and "1  3  5" are handled correctly.
        selected = raw.split()
        tokens = []
        valid = True
        for s in selected:
            # Rejects the whole selection, if any single entry is not in the MODULES dict.
            if s not in MODULES:
                warn(f"'{s}' is not a valid option.")
                valid = False
                break
            tokens.append(MODULES[s][0])
        if valid and tokens:
            # FOrces crawl to the fronnt of the list, since every test module depends on its output.
            if "crawl" not in tokens:
                info("Adding 'crawl' automatically (required by all test modules).")
                tokens = ["crawl"] + tokens
            # oins the token list into the comma-separated format expected by `--modules`.
            return ",".join(tokens)
        warn("Please select at least one valid module number.")


def pick_options():
    """Prompts the user for optional scan flags: verbose logging, and a proxy URL.

    Returns:
        tuple[bool, str or None]: A 2-element tuple, where the first element is `True` if verbose logging was requested, and the
        second is the proxy URL string e.g., `http://127.0.0.1:8080`, or `None` if no proxy was entered."""

    banner("─── Additional Options ───────────────────────────────")
    # Treats any inpujt other than "y" as no, defaulting to non-verbose for cleaner output.
    verbose = input("  Enable verbose (DEBUG) logging? [y/N]: ").strip().lower() == "y"
    proxy_raw = input(
        "  Proxy URL (blank to skip, e.g. http://127.0.0.1:8080): "
    ).strip()
    # Stores NOne rather than an empty string, so that the caller can use a simple truht check.
    proxy = proxy_raw if proxy_raw else None
    return verbose, proxy


# Run the scanner.
def run_scan(config_path, modules, verbose=False, proxy=None, output_dir="reports/"):
    """Builds and executes the `python -m scanner.main` command for a single target, inheriting the current terminal, so that the live
    scanner output prints in real time.

    Args:
        config_path (str): Path to the target YAML config file, e.g., `configs/juiceshop.yaml`.

        modules (str): The `--modules` value to pass, either `all`, or a comma-separated token string e.g., `crawl.idor`.

        verbose (bool): If `True`, appends `--verbose` to the command so the scanner logs at `DEBUG` level. Defaults `False`.

        proxy (str or None): A proxy URL to pass via `--proxy`, e.g., http://127.0.0.1:8080. Pass `NOne` to skip. Defaults to `NOne`.

        output_dir (str): Directory where the HTML, and JSON reports are written. Defaults to `reports/`."""

    # Builds the command list, using `sys.executable`, so that the correct venv Python is always used.
    cmd = [
        sys.executable,
        "-m",
        "scanner.main",
        "--config",
        config_path,
        "--output-dir",
        output_dir,
        "--modules",
        modules,
    ]
    # Appends the optional flags, only when they were actualy requested, keeping the command minimal.
    if verbose:
        cmd.append("--verbose")
    if proxy:
        cmd += ["--proxy", proxy]

    banner(f"─── Running scan: {config_path} ─────────────────────")
    # Prints the full command, so that the user can repdouce, or modify it manually if needed.
    info(f"Command: {' '.join(cmd)}")
    print()
    # Hands control to the scanner process, inheriting stdin/stdout so that live outputs print normally.
    subprocess.run(cmd)


def main():
    """Entry point for the launcher. RUns all 5 phases in sequence: DOcker setup, readiness polling, account creation, interactive scan config,
    and scan execution. Exits with code 1, if either DOcker container fails to start, or either target fails its reeadiness check."""

    # Prints the launcher banner.
    print(f"""
{C.BOLD}{C.CYAN}
 |--------------------------------------------------|
 |       Logic Flaw Scanner  —  Launch Setup        |
 |       -----------------------------------        |
 |       Annabel Molloy                             |
 |--------------------------------------------------|
{C.RESET}""")

    # Checks whether containers are already running and accounts already exist before running setup.
    # If everything is in place from a previous run, the 3 setup steps are skipped entirely.
    info("Checking whether environment is already configured...")
    already_configured = _check_configured()

    if already_configured:
        ok("Environment already configured — skipping setup.")
    else:
        info("Environment not ready — running full setup.")

        # Step 1 docker setup.
        banner("─── Step 1: Starting Docker containers ──────────────")
        # ENsures that both containers are running, before waiting for HTTP readiness.
        js_ok = ensure_container(
            "juice-shop", "bkimminich/juice-shop:v17.1.1", "3000:3000"
        )
        dvwa_ok = ensure_container("dvwa", "vulnerables/web-dvwa", "8080:80")

        # Exits immediately if either container failed to start, since neither scan target would be reacable.
        if not js_ok:
            err("Failed to start Juice Shop container. Exiting.")
            sys.exit(1)
        if not dvwa_ok:
            err("Failed to start DVWA container. Exiting.")
            sys.exit(1)

        # Step 2 wait for readiness.
        banner("─── Step 2: Waiting for targets to be ready ─────────")
        # Polls HTTP beforee attempting account setp, which would fail if the app hasnt finished booting.
        if not wait_for_http("http://localhost:3000", "Juice Shop"):
            err("Juice Shop did not start in time.")
            sys.exit(1)
        # Waits for MySQL separately because DVWA's web interface can be up before the database is ready.
        if not wait_for_dvwa_mysql():
            err("DVWA MySQL did not become ready.")
            sys.exit(1)

        # Step 3 account setup.
        banner("─── Step 3: Creating test accounts ──────────────────")
        # Sets up both targets unconditionally, INSERT IGNORE, and password reset make both reusable.
        setup_juice_shop_accounts()
        setup_dvwa_accounts()

    # Step 4 interactive scan configuration.
    banner("─── Step 4: Configure your scan ─────────────────────")
    targets = pick_target()
    modules = pick_scan_type()
    verbose, proxy = pick_options()

    # Step 5 run.
    for target_name, config_path in targets:
        # Creates a per target subdirectory. so that JS, and DVWA, reports dont overwrite each other.
        out_dir = f"reports/{target_name}/"
        os.makedirs(out_dir, exist_ok=True)
        run_scan(config_path, modules, verbose=verbose, proxy=proxy, output_dir=out_dir)

    banner("─── All scans complete ───────────────────────────────")

    ok("Reports written to reports/")


if __name__ == "__main__":
    main()
