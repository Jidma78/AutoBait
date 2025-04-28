#!/usr/bin/env python3
import asyncio
import asyncssh
import logging
import pathlib
import uuid
import datetime
import json

from agent_llm import llm_ask
from filesystem import filesystem, hidden_files, file_contents, file_metadata

# JSONL logging
LOG_PATH = pathlib.Path("output/log/honeypot.jsonl")
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
PROFILE_PROMPT_TEMPLATE = (pathlib.Path("prompt/profile_attacker.txt")).read_text()

logger = logging.getLogger("autobait")
logger.setLevel(logging.INFO)
logger.addHandler(logging.FileHandler(LOG_PATH, encoding="utf-8"))

def log_event(**fields):
    try:
        record = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
            **fields
        }
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"[DEBUG] Event logged into {LOG_PATH}")
    except Exception as e:
        print(f"[❌] Log writing error: {e}")

class HoneypotSSH(asyncssh.SSHServer):
    AUTHORIZED_USERS = {
        "root": "chillout",
        "devops": "Bigcorp2023!"
    }

    def connection_made(self, conn):
        self.peer_ip = conn.get_extra_info('peername')[0]

    def password_auth_supported(self): return True
    def public_key_auth_supported(self): return False

    def validate_password(self, username, password):
        valid_pwd = self.AUTHORIZED_USERS.get(username)
        return valid_pwd and password == valid_pwd

    def session_requested(self): return True



async def handle_session(process: asyncssh.SSHServerProcess):
    current_user = "devops"
    cwd = "/home/devops"
    installed_bins = set()
    session_id = f"session-{uuid.uuid4()}"
    session_commands = []

    async def prompt():
        suffix = "#" if current_user == "root" else "$"
        process.stdout.write(f"{current_user}@web-01:{cwd}{suffix} ")
        await process.stdout.drain()

    process.stdout.write(f"Welcome back, {current_user}.\n")
    process.stdout.write(f"Last login: {datetime.datetime.now(datetime.timezone.utc):%c}\n")
    await process.stdout.drain()
    await prompt()

    try:
        while not process.stdin.at_eof():
            line = await process.stdin.readline()
            if not line:
                break
            cmd = line.strip()
            if not cmd:
                await prompt()
                continue

            session_commands.append(cmd)

            # Gestion de exit/quit
            if cmd in ("exit", "quit"):
                if current_user == "root":
                    current_user = "devops"
                    cwd = "/home/devops"
                    await prompt()
                    continue
                else:
                    process.stdout.write("Bye!\n")
                    await process.stdout.drain()
                    break

            # Gestion du su
            if cmd.startswith("su"):
                if cmd.strip() == "su" or cmd.strip() == "su root":
                    process.stdout.write("Password: ")
                    await process.stdout.drain()
                    password = await process.stdin.readline()
                    if password.strip() == "chillout":
                        current_user = "root"
                        cwd = "/"
                        process.stdout.write("\n")
                    else:
                        process.stdout.write("su: Authentication failure\n")
                    await process.stdout.drain()
                else:
                    process.stdout.write(f"su: user {cmd.split()[1]} does not exist\n")
                    await process.stdout.drain()
                await prompt()
                continue

            # Toutes tes commandes normales ici (cd, ls, cat, apt install, etc)
            # cd
            if cmd.startswith("cd"):
                parts = cmd.split()
                if len(parts) > 1:
                    if parts[1] == "..":
                        cwd = "/" if cwd.count("/") <= 1 else "/".join(cwd.rstrip("/").split("/")[:-1])
                    elif parts[1] in ("~", "/"):
                        cwd = "/home/devops" if current_user == "devops" else "/"
                    else:
                        new_cwd = resolve_path(cwd, parts[1])
                        if new_cwd in filesystem:
                            cwd = new_cwd
                        else:
                            process.stdout.write(f"bash: cd: {parts[1]}: No such file or directory\n")
                else:
                    cwd = "/home/devops" if current_user == "devops" else "/"

            elif cmd == "pwd":
                process.stdout.write(cwd + "\n")

            elif cmd.startswith("apt install"):
                parts = cmd.split()
                if len(parts) >= 3:
                    package = parts[2]
                    installed_bins.add(package)
                    await simulate_apt_install(process, package)
                else:
                    process.stdout.write("Usage: apt install <package>\n")

            elif cmd.split()[0] in installed_bins:
                binary = cmd.split()[0]
                args = cmd.split()[1:]
                if binary == "nmap":
                    await simulate_nmap(process, args)
                else:
                    process.stdout.write(f"{cmd}: simulated execution\n")

            elif cmd in ("whoami", "hostname", "uname -a", "id", "history", "ifconfig", "netstat -tulnp", "ps aux"):
                await simulate_builtin_command(process, cmd)

            elif cmd.startswith("cat "):
                parts = cmd.split(maxsplit=1)
                if len(parts) == 2:
                    path = resolve_path(cwd, parts[1])

                    # Permissions check
                    if not current_user == "root" and (path.startswith("/root") or path.startswith("/etc/shadow")):
                        process.stdout.write(f"cat: {parts[1]}: Permission denied\n")
                    else:
                        content = file_contents.get(path)
                        if content is not None:
                            process.stdout.write(content + "\n")
                        else:
                            process.stdout.write(f"cat: {parts[1]}: No such file or directory\n")
                else:
                    process.stdout.write("Usage: cat <file>\n")

            elif cmd == "ls":
                visible = filesystem.get(cwd, [])
                process.stdout.write("  ".join(visible) + "\n")

            elif cmd in ("ls -a", "ls -la", "ls -al"):
                visible = filesystem.get(cwd, [])
                hidden = hidden_files.get(cwd, [])
                all_files = [".", ".."] + visible + hidden
                lines = [
                    "drwxr-xr-x 2 root root 4096 Apr 5 10:42 .",
                    "drwxr-xr-x 2 root root 4096 Apr 5 10:42 .."
                ]
                for f in visible + hidden:
                    meta = file_metadata.get(f, f"-rw-r--r-- 1 root root 4096 {datetime.date.today().strftime('%b %d')} {f}")
                    lines.append(meta)
                process.stdout.write("\n".join(lines) + "\n")
            
            elif cmd == "ls -l":
                visible = filesystem.get(cwd, [])
                lines = []
                for f in visible:
                    meta = file_metadata.get(f, f"-rw-r--r-- 1 root root 4096 {datetime.date.today().strftime('%b %d')} {f}")
                    lines.append(meta)
                process.stdout.write("\n".join(lines) + "\n")

            else:
                # Unknown command => send to LLM
                response = await llm_ask(cmd)
                if response.startswith("[❌"):
                    process.stdout.write(f"bash: {cmd}: command not found\n")
                else:
                    response_lines = response.strip().splitlines()
                    filtered_lines = [line for line in response_lines if not line.strip().endswith("$") and not line.strip().endswith("#")]
                    cleaned_response = "\n".join(filtered_lines)
                    process.stdout.write(cleaned_response + "\n")

            await process.stdout.drain()
            await prompt()

    finally:
        # Profiling always happens when session ends
        if session_commands:
            await profile_attacker(session_commands, process, session_id)


async def profile_attacker(commands, process, session_id):
    if not commands:
        print("[DEBUG] No commands to profile")
        return

    ip = process.get_extra_info('peername')[0]

    prompt_data = {
        "ip": ip,
        "commands": commands
    }

    try:
        print(f"[DEBUG] Starting profiling for {ip}...")
        result = await llm_ask(prompt_data, profile_mode=True)

        # Save in JSONL
        log_event(
            type="session_profile",
            attacker_ip=ip,
            session_commands=commands,
            attacker_profile=result,
        )

        # Save in text file
        session_dir = pathlib.Path("output/sessions")
        session_dir.mkdir(parents=True, exist_ok=True)
        report_path = session_dir / f"{session_id}.txt"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"Session ID: {session_id}\n")
            f.write(f"Attacker IP: {ip}\n\n")
            f.write("=== Commands Executed ===\n")
            f.write("\n".join(commands))
            f.write("\n\n=== Profiling Report ===\n")
            f.write(result)

        print(f"[📋] Profiling report created: {report_path}")

    except Exception as e:
        print(f"[❌] Profiling failed: {e}")

def resolve_path(cwd, path):
    if path.startswith("/"):
        return path.rstrip("/")
    if cwd == "/":
        return f"/{path}"
    return f"{cwd}/{path}"

async def simulate_builtin_command(process, cmd):
    outputs = {
        "whoami": "root\n",
        "hostname": "web-01.bigcorp.local\n",
        "uname -a": "Linux web-01 5.15.0-76-generic #83~20.04.1-Ubuntu SMP x86_64 GNU/Linux\n",
        "id": "uid=0(root) gid=0(root) groups=0(root)\n",
        "history": " 1  ls -la\n 2  cat /etc/passwd\n 3  exit\n",
        "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n    inet 192.168.1.27  netmask 255.255.255.0\n",
        "netstat -tulnp": "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n",
        "ps aux": "root         1  0.0  0.1  16832  1244 ?        Ss   Apr26   0:01 /sbin/init\nroot       512  0.0  0.2  23512  2348 ?        Ss   Apr26   0:00 /usr/sbin/sshd\n",
    }
    process.stdout.write(outputs.get(cmd, ""))
    await process.stdout.drain()

async def simulate_apt_install(process, package):
    lines = [
        "Reading package lists... Done",
        "Building dependency tree... Done",
        "Reading state information... Done",
        f"The following NEW packages will be installed:",
        f"  {package}",
        "0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.",
        "Need to get 7,587 kB of archives.",
        "After this operation, 28.6 MB of additional disk space will be used.",
        f"Get:1 http://archive.ubuntu.com/ubuntu focal/main amd64 {package} amd64 7.80+dfsg1-2build1 [7,587 kB]",
        "Fetched 7,587 kB in 2s (4,293 kB/s)",
        f"Selecting previously unselected package {package}.",
        "(Reading database ... 198673 files and directories currently installed.)",
        f"Preparing to unpack .../{package}_7.80+dfsg1-2build1_amd64.deb ...",
        f"Unpacking {package} (7.80+dfsg1-2build1) ...",
        f"Setting up {package} (7.80+dfsg1-2build1) ...",
        "Processing triggers for man-db (2.9.1-1) ..."
    ]
    for line in lines:
        process.stdout.write(line + "\n")
        await process.stdout.drain()
        await asyncio.sleep(0.5)

async def simulate_nmap(process, args):
    if not args:
        process.stdout.write("Nmap 7.80 ( https://nmap.org )\nUsage: nmap <target>\n")
        await process.stdout.drain()
        return

    target_ip = args[0]

    if target_ip.startswith("192.168.1."):
        await asyncio.sleep(1)
        process.stdout.write(f"Starting Nmap 7.80 ( https://nmap.org ) at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        await process.stdout.drain()
        await asyncio.sleep(2)

        if target_ip.endswith(".0"):
            hosts = {
                "192.168.1.1": ["22/tcp open ssh", "443/tcp open https"],
                "192.168.1.2": ["22/tcp open ssh"],
                "192.168.1.100": ["22/tcp open ssh", "80/tcp open http", "3306/tcp open mysql"]
            }
            for host, ports in hosts.items():
                process.stdout.write(f"Nmap scan report for {host}\nHost is up (0.001s latency).\n")
                await process.stdout.drain()
                await asyncio.sleep(1)
                if ports:
                    process.stdout.write("PORT     STATE SERVICE\n")
                    for p in ports:
                        process.stdout.write(f"{p}\n")
                    await asyncio.sleep(1)
            process.stdout.write("\nNmap done: 256 IP addresses (3 hosts up) scanned.\n")
        else:
            process.stdout.write(f"Nmap scan report for {target_ip}\n")
            await asyncio.sleep(1)
            process.stdout.write("Host is up (0.00030s latency).\n")
            await asyncio.sleep(1)
            process.stdout.write("Not shown: 998 closed ports\n")
            await asyncio.sleep(1)
            process.stdout.write("PORT     STATE SERVICE\n22/tcp   open  ssh\n80/tcp   open  http\n")
            await asyncio.sleep(1)
            process.stdout.write(f"Nmap done: 1 IP address (1 host up) scanned in 5.58 seconds\n")
    else:
        await asyncio.sleep(1)
        process.stdout.write(f"Nmap scan report for {target_ip}\nHost is down.\nNmap done: 1 IP address (0 hosts up) scanned.\n")

    await process.stdout.drain()

async def main():
    print("[🔥] Autobait SSH Honeypot launched on port :2222")
    await asyncssh.listen(
        host='0.0.0.0',
        port=2222,
        server_factory=HoneypotSSH,
        process_factory=handle_session,
        server_host_keys=['.ssh_keys/ssh_host_key'],
    )
    await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (OSError, asyncssh.Error) as e:
        print(f"[❌] SSH error: {e}")
