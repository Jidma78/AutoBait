import datetime

# Virtual file system structure
filesystem = {
    "/": ["opt", "home", "var", "etc", "srv", "root"],
    "/opt": ["jenkins"],
    "/opt/jenkins": ["deploy.sh", "scripts"],
    "/opt/jenkins/scripts": ["build.sh", "deploy_config.yaml"],
    "/var": ["backup", "log"],
    "/var/backup": ["mysql"],
    "/var/backup/mysql": ["prod_2025-04-05.sql.gz"],
    "/var/log": ["auth.log", "syslog"],
    "/srv": ["www"],
    "/srv/www": ["legacy_php"],
    "/srv/www/legacy_php": ["index.php", "info.php", "config.php"],
    "/home": ["devops"],
    "/home/devops": ["Documents", "Downloads", ".aws", ".ssh", ".bash_history", ".viminfo", "docker-compose.yml"],
    "/home/devops/Documents": ["resume.docx", "project_notes.txt", "vault.db"],
    "/home/devops/Downloads": ["terraform.zip", "awscli.deb"],
    "/home/devops/.aws": ["credentials", "config"],
    "/home/devops/.ssh": ["id_rsa", "known_hosts"],
    "/root": [".bashrc", ".profile", ".ssh"],
    "/root/.ssh": ["authorized_keys"],
    "/etc": ["crontab", "passwd", "shadow", "hostname", "hosts"],
}

# Hidden files (visible with 'ls -a')
hidden_files = {
    "/": [".bashrc", ".profile"],
    "/home/devops": [".bash_history", ".viminfo"],
    "/root": [".bashrc", ".profile"],
}

# Content of each file
file_contents = {
    "/opt/jenkins/deploy.sh": """#!/bin/bash
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/XXXX/YYYY/ZZZZ"
git pull
sudo systemctl restart apache2
""",
    "/opt/jenkins/scripts/build.sh": """#!/bin/bash
echo "Starting Jenkins build pipeline..."
""",
    "/opt/jenkins/scripts/deploy_config.yaml": """deployment:
  environment: production
  region: eu-west-3
""",
    "/home/devops/.aws/credentials": """[default]
aws_access_key_id=AKIAEXAMPLEKEY
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
""",
    "/home/devops/.aws/config": """[default]
region = eu-west-3
output = json
""",
    "/home/devops/Documents/resume.docx": "(binary file)",
    "/home/devops/Documents/project_notes.txt": "TODO: Improve Jenkins deployment automation.\nReminder: Update vault credentials.",
    "/home/devops/Documents/vault.db": "(binary encrypted vault file)",
    "/home/devops/Downloads/terraform.zip": "(binary file)",
    "/home/devops/Downloads/awscli.deb": "(binary file)",
    "/home/devops/docker-compose.yml": """version: '3'
services:
  app:
    image: myapp:latest
    ports:
      - "80:80"
""",
    "/etc/crontab": """# /etc/crontab
0 * * * * root /usr/bin/cleanup.sh
""",
    "/etc/passwd": """root:x:0:0:root:/root:/bin/bash
devops:x:1001:1001:DevOps User:/home/devops:/bin/bash
""",
    "/etc/shadow": """root:$6$rounds=656000$abcdefg$:17000::::::
devops:$6$rounds=656000$12345678$:17000::::::
""",
    "/etc/hostname": "web-01\n",
    "/etc/hosts": """127.0.0.1 localhost
192.168.1.27 web-01.bigcorp.local
""",
    "/var/log/auth.log": """Apr 26 14:32:10 web-01 sshd[1234]: Accepted password for root from 192.168.1.198 port 50234 ssh2
""",
    "/var/log/syslog": """Apr 26 14:30:00 web-01 systemd[1]: Started Daily Cleanup of Temporary Directories.
""",
    "/root/.ssh/authorized_keys": "ssh-rsa AAAAB3Nza... user@machine\n",
    "/home/devops/.ssh/id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n",
    "/home/devops/.ssh/known_hosts": "github.com,192.30.253.112 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA...",
    "/srv/www/legacy_php/config.php": "<?php\n$DB_PASSWORD='secretpassword';\n?>",
    "/srv/www/legacy_php/index.php": "<?php echo 'Hello, world!'; ?>",
    "/srv/www/legacy_php/info.php": "<?php phpinfo(); ?>",
    "/root/.bashrc": "# ~/.bashrc\nsource /etc/bashrc\n",
    "/root/.profile": "# ~/.profile\nPATH=$PATH:$HOME/bin\nexport PATH\n",
    "/home/devops/.bash_history": "cat /etc/passwd\nls -la\ncat ~/.aws/credentials\nexit\n",
    "/home/devops/.viminfo": "",
}

# Simulated 'ls -l' output metadata
file_metadata = {
    "opt": "drwxr-xr-x 2 root root 4096 Apr 5 10:42 opt",
    "home": "drwxr-xr-x 2 root root 4096 Apr 5 10:42 home",
    "var": "drwxr-xr-x 2 root root 4096 Apr 5 10:42 var",
    "etc": "drwxr-xr-x 2 root root 4096 Apr 5 10:42 etc",
    "srv": "drwxr-xr-x 2 root root 4096 Apr 5 10:42 srv",
    "root": "drwxr-xr-x 2 root root 4096 Apr 5 10:42 root",
    "jenkins": "drwxr-xr-x 2 root root 4096 Apr 5 11:10 jenkins",
    "deploy.sh": "-rw-r--r-- 1 root root 289 Apr 5 11:10 deploy.sh",
    "scripts": "drwxr-xr-x 2 root root 4096 Apr 5 11:10 scripts",
    "Documents": "drwxr-xr-x 2 devops devops 4096 Apr 29 11:10 Documents",
    "Downloads": "drwxr-xr-x 2 devops devops 4096 Apr 29 11:10 Downloads",
    ".aws": "drwx------ 2 devops devops 4096 Apr 29 11:10 .aws",
    ".ssh": "drwx------ 2 devops devops 4096 Apr 29 11:10 .ssh",
    ".bash_history": "-rw------- 1 devops devops 4096 Apr 29 11:10 .bash_history",
    ".viminfo": "-rw------- 1 devops devops 4096 Apr 29 11:10 .viminfo",
    "docker-compose.yml": "-rw-r--r-- 1 devops devops 309 Apr 29 11:10 docker-compose.yml",
    "auth.log": "-rw-r--r-- 1 root root 1240 Apr 26 15:00 auth.log",
    "syslog": "-rw-r--r-- 1 root root 1240 Apr 26 15:00 syslog",
}
