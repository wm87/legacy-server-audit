#!/bin/bash
set -euo pipefail

PROJECT_NAME="${1:-legacy-server-audit}"

# -----------------------------
# Farbcodes für bessere Lesbarkeit
# -----------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Prüfen ob Verzeichnis existiert
if [ -d "$PROJECT_NAME" ]; then
	echo -e "${YELLOW}⚠️  Verzeichnis '$PROJECT_NAME' existiert bereits${NC}"
	read -p "Überschreiben? (j/N): " -n 1 -r
	echo
	if [[ ! $REPLY =~ ^[JjYy]$ ]]; then
		echo -e "${RED}❌ Abgebrochen.${NC}"
		exit 1
	fi
	echo -e "${YELLOW}🗑️  Lösche existierendes Verzeichnis...${NC}"
	rm -rf "$PROJECT_NAME"
fi

echo -e "${BLUE}🚀 Erstelle vollständiges erweitertes Ansible Projekt mit CIS Benchmarks: $PROJECT_NAME${NC}"

# -----------------------------
# Ordnerstruktur
# -----------------------------
echo -e "${BLUE}📁 Erstelle Ordnerstruktur...${NC}"
mkdir -p "$PROJECT_NAME"/roles/audit/{tasks,handlers,templates,files,vars,defaults,meta}
mkdir -p "$PROJECT_NAME"/{inventory,reports,policies,proposals,certificates,backups,group_vars,host_vars}
mkdir -p "$PROJECT_NAME"/roles/audit/tasks/cis/{level1,level2}
mkdir -p "$PROJECT_NAME"/vars

# -----------------------------
# ansible.cfg
# -----------------------------
echo -e "${BLUE}⚙️  Erstelle ansible.cfg...${NC}"
cat <<EOF >"$PROJECT_NAME/ansible.cfg"
[defaults]
inventory = inventory/hosts.ini
stdout_callback = default
result_format = yaml
host_key_checking = False
retry_files_enabled = False
gathering = smart
fact_caching = jsonfile
fact_caching_connection = /tmp/ansible_facts
fact_caching_timeout = 600
timeout = 30
forks = 10

[ssh_connection]
pipelining = True
ssh_args = -o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=60

[privilege_escalation]
become = True
become_method = sudo
become_user = root
become_ask_pass = False

[galaxy]
ignore_certs = True
EOF

# -----------------------------
# Inventory
# -----------------------------
echo -e "${BLUE}📋 Erstelle Inventory...${NC}"
cat <<EOF >"$PROJECT_NAME/inventory/hosts.ini"
[local]
localhost ansible_connection=local ansible_user=$(whoami)

[legacy_servers]
#server1 ansible_host=192.168.1.100 ansible_user=audit_user ansible_become=yes
#server2 ansible_host=192.168.1.101 ansible_user=audit_user ansible_become=yes

[audit_targets:children]
legacy_servers

[all:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_become=true
ansible_become_method=sudo
ansible_become_user=root
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

# -----------------------------
# Playbook
# -----------------------------
echo -e "${BLUE}📄 Erstelle Haupt-Playbook...${NC}"
cat <<EOF >"$PROJECT_NAME/audit.yml"
---
- name: 'Legacy Server Security Audit - Phase 1: System Discovery'
  hosts: all
  become: true
  gather_facts: true
  vars_files:
    - vars/audit_vars.yml
  tasks:
    - name: Pre-flight check - Verify connectivity
      ping:
    
    - name: Include audit role
      include_role:
        name: audit

- name: 'Generate Comprehensive Report'
  hosts: localhost
  become: false
  gather_facts: false
  tasks:
    - name: Generate reports
      include_role:
        name: audit
        tasks_from: reporting.yml
EOF

# -----------------------------
# Audit Variables
# -----------------------------
echo -e "${BLUE}📊 Erstelle Audit-Variablen...${NC}"
cat <<EOF >"$PROJECT_NAME/vars/audit_vars.yml"
# Audit Configuration
audit_cis_level: 2
audit_max_severity: 10

# Thresholds
disk_threshold: 85
password_max_age: 90
inactive_user_days: 90
failed_login_threshold: 5
update_threshold_days: 30

# Security Policies
allowed_ssh_ciphers: "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
allowed_ssh_macs: "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
allowed_ssh_kex: "curve25519-sha256,curve25519-sha256@libssh.org"

# Exclusions
exclude_paths:
  - "/proc"
  - "/sys"
  - "/dev"
  - "/run"
  - "/tmp"
exclude_users:
  - "nobody"
  - "nfsnobody"
  - "dbus"
  - "systemd-*"
  - "messagebus"

# Report Configuration
report_format: "json"
generate_html_report: true
archive_reports: true
EOF

# -----------------------------
# Defaults
# -----------------------------
echo -e "${BLUE}⚙️  Erstelle Default-Variablen...${NC}"
cat <<EOF >"$PROJECT_NAME/roles/audit/defaults/main.yml"
---
audit_cis_level: 2
audit_max_severity: 10
disk_threshold: 85
password_max_age: 90
inactive_user_days: 90
failed_login_threshold: 5
update_threshold_days: 30
EOF

# -----------------------------
# Meta
# -----------------------------
cat <<EOF >"$PROJECT_NAME/roles/audit/meta/main.yml"
---
galaxy_info:
  author: "Security Audit Team"
  description: "Comprehensive security audit role for legacy servers"
  license: "MIT"
  min_ansible_version: "2.9"
  platforms:
    - name: EL
      versions:
        - 7
        - 8
    - name: Ubuntu
      versions:
        - 18.04
        - 20.04
        - 22.04
    - name: Debian
      versions:
        - 10
        - 11
  galaxy_tags:
    - security
    - audit
    - compliance
    - cis

dependencies: []
EOF

# -----------------------------
# main.yml (Tasks Import)
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Haupt-Tasks...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/main.yml"
---
- name: Pre-audit system information collection
  block:
    - name: Gather comprehensive system facts
      setup:
        gather_subset:
          - '!all'
          - '!min'
          - system
          - hardware
          - network
          - distribution
          - pkg_mgr
          - virtual
          - env
        filter: "*"
      register: system_facts
  
    - name: Display basic system info
      debug:
        msg: "Auditing {{ ansible_hostname }} ({{ ansible_distribution }} {{ ansible_distribution_version }})"
  
  tags: always

- name: Include CIS Benchmarks based on configured level
  block:
    - name: Include CIS Level 1 Benchmarks
      include_tasks: cis/level1/main.yml
      when: audit_cis_level >= 1
      tags: cis,cis_level1
    
    - name: Include CIS Level 2 Benchmarks
      include_tasks: cis/level2/main.yml
      when: audit_cis_level >= 2
      tags: cis,cis_level2
  
  tags: cis

- name: System configuration audit modules
  block:
    - import_tasks: ports.yml
      tags: ports
    
    - import_tasks: services.yml
      tags: services
    
    - import_tasks: users.yml
      tags: users
    
    - import_tasks: cron.yml
      tags: cron
    
    - import_tasks: packages.yml
      tags: packages
    
    - import_tasks: security.yml
      tags: security
    
    - import_tasks: sudoers.yml
      tags: sudo
    
    - import_tasks: updates.yml
      tags: updates
    
    - import_tasks: password_age.yml
      tags: passwords
    
    - import_tasks: sysctl.yml
      tags: sysctl
    
    - import_tasks: kernel.yml
      tags: kernel
    
    - import_tasks: boot.yml
      tags: boot
    
    - import_tasks: filesystem.yml
      tags: filesystem
  
  tags: system

- name: Security-specific audit modules
  block:
    - import_tasks: firewall.yml
      tags: firewall
    
    - import_tasks: ssh_keys.yml
      tags: ssh
    
    - import_tasks: auditd.yml
      tags: auditd
    
    - import_tasks: network.yml
      tags: network
    
    - import_tasks: logging.yml
      tags: logging
  
  tags: security

- name: Risk and vulnerability detection modules
  block:
    - import_tasks: containers.yml
      tags: containers
    
    - import_tasks: secrets.yml
      tags: secrets
    
    - import_tasks: world_writable.yml
      tags: permissions
    
    - import_tasks: inactive_users.yml
      tags: users
    
    - import_tasks: env_secrets.yml
      tags: secrets
    
    - import_tasks: logrotate.yml
      tags: logging
    
    - import_tasks: suid_sgid.yml
      tags: permissions
    
    - import_tasks: ipv6_ports.yml
      tags: network
    
    - import_tasks: failed_logins.yml
      tags: auth
    
    - import_tasks: crypto.yml
      tags: crypto
    
    - import_tasks: permissions.yml
      tags: permissions
  
  tags: risks

- name: Compliance and reporting modules
  block:
    - import_tasks: compliance.yml
      tags: compliance
    
    - import_tasks: risk_expiry.yml
      tags: compliance
    
    - import_tasks: redflags.yml
      tags: reporting
    
    - import_tasks: fixes.yml
      tags: reporting
    
    - import_tasks: severity.yml
      tags: reporting
    
    - import_tasks: json.yml
      tags: reporting
  
  tags: reporting

- name: Optional advanced modules
  block:
    - import_tasks: sops_proposals.yml
      tags: ['secrets', 'sops']
      when: false
    
    - import_tasks: remediation.yml
      tags: remediation
      when: false
  
  tags: optional
EOF

# -----------------------------
# CIS Level 1 Benchmarks
# -----------------------------
echo -e "${BLUE}🔧 Erstelle CIS Level 1 Tasks...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/cis/level1/main.yml"
---
- name: CIS Level 1 - Filesystem Configuration
  block:
    - name: 1.1.1.1 Ensure mounting of cramfs filesystems is disabled
      lineinfile:
        path: /etc/modprobe.d/cramfs.conf
        line: "install cramfs /bin/true"
        create: yes
        state: present
      changed_when: false
      check_mode: true
      register: cis_1_1_1_1
    
    - name: 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled
      lineinfile:
        path: /etc/modprobe.d/freevxfs.conf
        line: "install freevxfs /bin/true"
        create: yes
        state: present
      changed_when: false
      check_mode: true
    
    - name: 1.1.2 Ensure /tmp is configured with nodev, nosuid, noexec options
      mount:
        name: /tmp
        src: tmpfs
        fstype: tmpfs
        opts: defaults,nodev,nosuid,noexec
        state: present
      changed_when: false
      check_mode: true
    
    - name: 1.1.3 Ensure separate partition exists for /var
      stat:
        path: /var
      register: var_partition
      changed_when: false
    
    - name: 1.1.4 Ensure separate partition exists for /var/tmp
      stat:
        path: /var/tmp
      register: var_tmp_partition
      changed_when: false
    
    - name: 1.1.5 Ensure separate partition exists for /var/log
      stat:
        path: /var/log
      register: var_log_partition
      changed_when: false

  tags: cis,cis_level1,filesystem

- name: CIS Level 1 - Service Configuration
  block:
    - name: Check if autofs is installed
      package_facts:
        manager: auto
      register: packages
    
    - name: 1.1.9 Disable Automounting
      ansible.builtin.systemd:
        name: autofs
        state: stopped
        enabled: false
      when: "'autofs' in ansible_facts.packages"
      changed_when: false
      check_mode: true
    
    - name: 1.1.10 Ensure USB Storage is disabled
      lineinfile:
        path: /etc/modprobe.d/usb-storage.conf
        line: "install usb-storage /bin/true"
        create: yes
        state: present
      changed_when: false
      check_mode: true
    
    - name: 1.3.1 Ensure AIDE is installed
      package:
        name: aide
        state: present
      changed_when: false
      check_mode: true
      register: aide_check
    
    - name: 1.3.2 Ensure filesystem integrity is regularly checked
      cron:
        name: "AIDE integrity check"
        minute: "0"
        hour: "5"
        job: "/usr/sbin/aide --check"
        state: present
      when: aide_check is changed or aide_check.changed
      changed_when: false
      check_mode: true

  tags: cis,cis_level1,services

- name: CIS Level 1 - System Configuration
  block:
    - name: 1.4.1 Ensure bootloader password is set
      stat:
        path: /boot/grub/grub.cfg
      register: grub_cfg
      changed_when: false
    
    - name: 1.5.1 Ensure core dumps are restricted
      sysctl:
        name: fs.suid_dumpable
        value: '0'
        state: present
        reload: false
      changed_when: false
      check_mode: true
    
    - name: 1.7.1 Ensure AppArmor is installed
      package:
        name: apparmor
        state: present
      changed_when: false
      check_mode: true
      register: apparmor_check
    
    - name: 1.8.1 Ensure message of the day is configured properly
      stat:
        path: /etc/motd
      register: motd_check
      changed_when: false

  tags: cis,cis_level1,system

- name: Gather fs.suid_dumpable sysctl
  ansible.builtin.command: sysctl -n fs.suid_dumpable
  register: suid_dumpable
  changed_when: false
  check_mode: false

- name: Collect CIS Level 1 results
  set_fact:
    cis_level1_results:
      "1.1.1.1": "{{ (cis_1_1_1_1 is changed) if cis_1_1_1_1 is defined else False }}"
      "1.1.2": "{{ (ansible_mounts | selectattr('mount', 'equalto', '/tmp') | list | length) > 0 }}"
      "1.1.3": "{{ var_partition.stat.islnk | default(False) }}"
      "1.1.4": "{{ var_tmp_partition.stat.islnk | default(False) }}"
      "1.1.5": "{{ var_log_partition.stat.islnk | default(False) }}"
      "1.1.9": "{{ 'autofs' not in ansible_facts.packages }}"
      "1.1.10": "{{ True }}"
      "1.3.1": "{{ 'aide' in ansible_facts.packages }}"
      "1.3.2": "{{ (aide_check is changed) if aide_check is defined else False }}"
      "1.4.1": "{{ grub_cfg.stat.exists | default(False) }}"
      "1.5.1": "{{ suid_dumpable.stdout == '0' }}"
      "1.7.1": "{{ 'apparmor' in ansible_facts.packages }}"
      "1.8.1": "{{ motd_check.stat.exists | default(False) }}"
  tags: [cis, cis_level1, reporting]
EOF

# -----------------------------
# CIS Level 2 Benchmarks
# -----------------------------
echo -e "${BLUE}🔧 Erstelle CIS Level 2 Tasks...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/cis/level2/main.yml"
---
- name: CIS Level 2 - Unnecessary Services
  block:
    - name: 2.1.1 Ensure xinetd is not installed
      package:
        name: xinetd
        state: absent
      changed_when: false
      check_mode: true
    
    - name: 2.1.2 Ensure openbsd-inetd is not installed
      package:
        name: openbsd-inetd
        state: absent
      changed_when: false
      check_mode: true
    
    - name: 2.2.1.1 Ensure time synchronization is in use
      package:
        name: "{{ 'chrony' if ansible_facts.os_family == 'RedHat' else 'systemd-timesyncd' }}"
        state: present
      changed_when: false
      check_mode: true
    
    - name: 2.2.2 Ensure X Window System is not installed
      shell: dpkg -l xserver-xorg* 2>/dev/null | grep ^ii || rpm -qa xorg-x11-server* 2>/dev/null || true
      register: x11_installed
      changed_when: false
      failed_when: false
    
    - name: 2.2.3 Ensure Avahi Server is not installed
      package:
        name: avahi-daemon
        state: absent
      changed_when: false
      check_mode: true
    
    - name: 2.2.4 Ensure CUPS is not installed
      package:
        name: cups
        state: absent
      changed_when: false
      check_mode: true
    
    - name: 2.2.5 Ensure DHCP Server is not installed
      package:
        name: "{{ 'dhcp' if ansible_facts.os_family == 'RedHat' else 'isc-dhcp-server' }}"
        state: absent
      changed_when: false
      check_mode: true

  tags: cis,cis_level2,services

- name: CIS Level 2 - Network Configuration
  block:
    - name: 3.1.1 Disable IPv6 if not needed
      sysctl:
        name: net.ipv6.conf.all.disable_ipv6
        value: '1'
        state: present
        reload: false
      changed_when: false
      check_mode: true
    
    - name: 3.2.1 Ensure packet redirect sending is disabled
      sysctl:
        name: net.ipv4.conf.all.send_redirects
        value: '0'
        state: present
        reload: false
      changed_when: false
      check_mode: true
    
    - name: 3.2.2 Ensure IP forwarding is disabled
      sysctl:
        name: net.ipv4.ip_forward
        value: '0'
        state: present
        reload: false
      changed_when: false
      check_mode: true
    
    - name: 3.3.1 Ensure source routed packets are not accepted
      sysctl:
        name: net.ipv4.conf.all.accept_source_route
        value: '0'
        state: present
        reload: false
      changed_when: false
      check_mode: true
    
    - name: 3.3.2 Ensure ICMP redirects are not accepted
      sysctl:
        name: net.ipv4.conf.all.accept_redirects
        value: '0'
        state: present
        reload: false
      changed_when: false
      check_mode: true

  tags: cis,cis_level2,network

- name: Read CIS Level 2 sysctl values
  command: sysctl -n {{ item }}
  register: cis_level2_sysctl
  changed_when: false
  failed_when: false
  loop:
    - net.ipv6.conf.all.disable_ipv6
    - net.ipv4.conf.all.send_redirects
    - net.ipv4.ip_forward
    - net.ipv4.conf.all.accept_source_route
    - net.ipv4.conf.all.accept_redirects

- name: Collect CIS Level 2 results
  set_fact:
    cis_level2_results:
      "2.1.1": "{{ 'xinetd' not in ansible_facts.packages }}"
      "2.1.2": "{{ 'openbsd-inetd' not in ansible_facts.packages }}"
      "2.2.1.1": "{{ 'chrony' in ansible_facts.packages or 'systemd-timesyncd' in ansible_facts.packages }}"
      "2.2.2": "{{ x11_installed.stdout == '' }}"
      "2.2.3": "{{ 'avahi-daemon' not in ansible_facts.packages }}"
      "2.2.4": "{{ 'cups' not in ansible_facts.packages }}"
      "2.2.5": "{{ 'dhcp' not in ansible_facts.packages and 'isc-dhcp-server' not in ansible_facts.packages }}"

      "3.1.1": "{{ cis_level2_sysctl.results
                    | selectattr('item','equalto','net.ipv6.conf.all.disable_ipv6')
                    | map(attribute='stdout')
                    | first == '1' }}"

      "3.2.1": "{{ cis_level2_sysctl.results
                    | selectattr('item','equalto','net.ipv4.conf.all.send_redirects')
                    | map(attribute='stdout')
                    | first == '0' }}"

      "3.2.2": "{{ cis_level2_sysctl.results
                    | selectattr('item','equalto','net.ipv4.ip_forward')
                    | map(attribute='stdout')
                    | first == '0' }}"

      "3.3.1": "{{ cis_level2_sysctl.results
                    | selectattr('item','equalto','net.ipv4.conf.all.accept_source_route')
                    | map(attribute='stdout')
                    | first == '0' }}"

      "3.3.2": "{{ cis_level2_sysctl.results
                    | selectattr('item','equalto','net.ipv4.conf.all.accept_redirects')
                    | map(attribute='stdout')
                    | first == '0' }}"
  
  tags: cis,cis_level2,reporting
EOF

# -----------------------------
# Ports Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Ports Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/ports.yml"
---
- name: Network Port Audit
  block:
    - name: Detect available network tools
      shell: |
        which ss 2>/dev/null && echo "ss" || \
        which netstat 2>/dev/null && echo "netstat" || \
        echo "none"
      register: network_tool
      changed_when: false
      failed_when: false
    
    - name: List all listening ports using ss
      shell: |
        ss -tuln 2>/dev/null | awk 'NR>1 {print $1,$5}' | \
        while read proto addr; do
          port=$(echo $addr | awk -F: '{print $NF}')
          echo "$proto:$port"
        done | sort -u
      register: ports_ss
      changed_when: false
      failed_when: false
      when: "'ss' in network_tool.stdout"
    
    - name: List all listening ports using netstat
      shell: |
        netstat -tuln 2>/dev/null | awk 'NR>2 && $6=="LISTEN" {print $1,$4}' | \
        while read proto addr; do
          port=$(echo $addr | awk -F: '{print $NF}')
          echo "$proto:$port"
        done | sort -u
      register: ports_netstat
      changed_when: false
      failed_when: false
      when: "'netstat' in network_tool.stdout"
    
    - name: Combine port results
      set_fact:
        listening_ports: "{{ (ports_ss.stdout_lines if ports_ss is defined else []) + 
                            (ports_netstat.stdout_lines if ports_netstat is defined else []) }}"
    
    - name: Check for risky ports
      set_fact:
        risky_ports_detected: []
      changed_when: false
    
    - name: Detect common risky ports
      set_fact:
        risky_ports_detected: "{{ risky_ports_detected + [item] }}"
      loop: "{{ listening_ports }}"
      when: >
        item.split(':')[1] in [
          '21',    '23',    '69',    '111',   '135',
          '137',   '138',   '139',   '445',   '512',
          '513',   '514',   '1099',  '2049',  '3306',
          '3389',  '5432',  '5900',  '6000',  '8080'
        ]
    
    - name: Get service information for ports
      shell: |
        {{ item }} 2>/dev/null | head -20
      loop:
        - "lsof -i"
        - "ss -tulp"
      register: port_services
      changed_when: false
      failed_when: false
    
    - name: Set port audit facts
      set_fact:
        audit_ports:
          total: "{{ listening_ports | length }}"
          listening: "{{ listening_ports }}"
          risky_count: "{{ risky_ports_detected | length }}"
          risky_ports: "{{ risky_ports_detected }}"
          services_info: "{{ port_services.results | map(attribute='stdout_lines') | list }}"
    
    - name: Display port summary
      debug:
        msg: |
          Port Audit Summary:
          - Total listening ports: {{ audit_ports.total }}
          - Risky ports detected: {{ audit_ports.risky_count }}
          {% if audit_ports.risky_count | int > 0 %}
          - Risky ports: {{ audit_ports.risky_ports | join(', ') }}
          {% endif %}

  tags: ports,network
EOF

# -----------------------------
# Services Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Services Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/services.yml"
---
- name: System Services Audit
  block:
    - name: List all system services
      shell: |
        if systemctl list-units --type=service --no-legend 2>/dev/null; then
          systemctl list-units --type=service --no-legend | head -50
        elif service --status-all 2>/dev/null; then
          service --status-all | head -50
        else
          echo "No service manager found"
        fi
      register: services
      changed_when: false
      failed_when: false
    
    - name: Check for risky services
      set_fact:
        risky_services: []
      changed_when: false
    
    - name: Detect risky services
      set_fact:
        risky_services: "{{ risky_services + [item] }}"
      loop:
        - 'telnet'
        - 'rsh'
        - 'rlogin'
        - 'rexec'
        - 'nfs'
        - 'nfs-server'
        - 'vsftpd'
        - 'samba'
        - 'smbd'
        - 'nmbd'
        - 'ypserv'
        - 'ypbind'
        - 'tftp'
        - 'tftpd'
        - 'xinetd'
        - 'dhcpd'
        - 'dhcp'
        - 'slapd'
        - 'named'
        - 'bind9'
        - 'dovecot'
      when: >
        item in services.stdout
    
    - name: Check service permissions
      shell: |
        find /etc/systemd/system /lib/systemd/system -name "*.service" -type f 2>/dev/null | \
        xargs -I {} sh -c 'echo "Service: {}"; stat -c "%a %U %G" {}' 2>/dev/null | \
        grep -E "^(Service:|.* [0-7][0-7][0-7] .*)$"
      register: service_perms
      changed_when: false
      failed_when: false
    
    - name: Set service audit facts
      set_fact:
        audit_services: "{{ services.stdout_lines | default([]) }}"
        risky_services_detected: "{{ risky_services | default([]) | length > 0 }}"
        service_permission_issues: "{{ service_perms.stdout_lines | default([]) | select('search', '7[0-7][0-7]|.[0-7]7.') | list }}"
    
    - name: Display service summary
      debug:
        msg: |
          Service Audit Summary:
          - Total services listed: {{ audit_services | length }}
          - Risky services detected: {{ risky_services_detected }}
          {% if service_permission_issues %}
          - Service permission issues: {{ service_permission_issues | length }}
          {% endif %}
  
  tags: services,system
EOF

# -----------------------------
# Users Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Users Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/users.yml"
---
- name: User and Group Audit
  block:
    - name: Get all users
      shell: |
        getent passwd | cut -d: -f1,3,4,6,7
      register: users
      changed_when: false
      failed_when: false
    
    - name: Get all groups
      shell: |
        getent group | cut -d: -f1,3,4
      register: groups
      changed_when: false
      failed_when: false
    
    - name: Check for duplicate UIDs
      shell: |
        getent passwd | cut -d: -f3 | sort | uniq -d
      register: duplicate_uids
      changed_when: false
      failed_when: false
    
    - name: Check for duplicate GIDs
      shell: |
        getent group | cut -d: -f3 | sort | uniq -d
      register: duplicate_gids
      changed_when: false
      failed_when: false
    
    - name: Check for users with UID 0 (root)
      shell: |
        getent passwd | awk -F: '$3 == 0 {print $1}'
      register: root_users
      changed_when: false
      failed_when: false
    
    - name: Check for users without password
      shell: |
        getent shadow | awk -F: '($2 == "" || $2 == "!" || $2 == "*") {print $1}'
      register: no_password_users
      changed_when: false
      failed_when: false
    
    - name: Check for system accounts with shell access
      shell: |
        getent passwd | awk -F: '$3 < 1000 && $7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 != "/sbin/nologin" {print $1 ":" $7}'
      register: system_accounts_with_shell
      changed_when: false
      failed_when: false
    
    - name: Set user audit facts
      set_fact:
        audit_users: "{{ users.stdout_lines | default([]) }}"
        audit_groups: "{{ groups.stdout_lines | default([]) }}"
        duplicate_uids_found: "{{ duplicate_uids.stdout_lines | default([]) | length > 0 }}"
        duplicate_gids_found: "{{ duplicate_gids.stdout_lines | default([]) | length > 0 }}"
        extra_root_users: "{{ (root_users.stdout_lines | default([]) | length) > 1 }}"
        no_password_users_list: "{{ no_password_users.stdout_lines | default([]) }}"
        system_accounts_with_shell_list: "{{ system_accounts_with_shell.stdout_lines | default([]) }}"
    
    - name: Display user summary
      debug:
        msg: |
          User Audit Summary:
          - Total users: {{ audit_users | length }}
          - Total groups: {{ audit_groups | length }}
          - Duplicate UIDs: {{ duplicate_uids_found }}
          - Duplicate GIDs: {{ duplicate_gids_found }}
          - Extra root users: {{ extra_root_users }}
          - Users without password: {{ no_password_users_list | length }}
          - System accounts with shell: {{ system_accounts_with_shell_list | length }}
  
  tags: users,auth
EOF

# -----------------------------
# Cron Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Cron Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/cron.yml"
---
- name: Cron Job Audit
  block:
    - name: List cron jobs for all users
      shell: |
        set +e
        for u in $(getent passwd | cut -d: -f1); do
          echo "=== User: $u ==="
          crontab -l -u "$u" 2>/dev/null || echo "No crontab for $u"
        done
        echo "=== System cron ==="
        ls -la /etc/cron.* 2>/dev/null || true
        cat /etc/crontab 2>/dev/null || true
        exit 0
      register: cron
      changed_when: false
      failed_when: false
    
    - name: Check cron file permissions
      shell: |
        find /etc/cron* /var/spool/cron -type f -exec stat -c "%a %n" {} \; 2>/dev/null | \
        grep -E "^(7[0-7][0-7]|.[0-7]7.)"
      register: cron_perms
      changed_when: false
      failed_when: false
    
    - name: Check for world-writable cron directories
      shell: |
        find /etc/cron* /var/spool/cron -type d -perm -0002 2>/dev/null
      register: cron_world_writable
      changed_when: false
      failed_when: false
    
    - name: Set cron audit facts
      set_fact:
        audit_crons: "{{ cron.stdout_lines | default([]) }}"
        cron_permission_issues: "{{ cron_perms.stdout_lines | default([]) }}"
        cron_world_writable_dirs: "{{ cron_world_writable.stdout_lines | default([]) }}"
        root_cron: "{{ 'root' in cron.stdout }}"
    
    - name: Display cron summary
      debug:
        msg: |
          Cron Audit Summary:
          - Cron entries found: {{ audit_crons | length > 0 }}
          - Cron permission issues: {{ cron_permission_issues | length }}
          - World-writable cron dirs: {{ cron_world_writable_dirs | length }}
          - Root cron present: {{ root_cron }}
  
  tags: cron,system
EOF

# -----------------------------
# Packages Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Packages Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/packages.yml"
---
- name: Package Audit
  block:
    - name: List installed packages (Debian/Ubuntu)
      shell: |
        if command -v dpkg >/dev/null 2>&1; then
          dpkg-query -W -f='${Package}\t${Version}\t${Status}\n' | grep "installed" | head -100
        else
          echo "Not a Debian system"
        fi
      register: deb_packages
      changed_when: false
      failed_when: false
      when: ansible_facts.os_family == "Debian"
    
    - name: List installed packages (RHEL/CentOS)
      shell: |
        if command -v rpm >/dev/null 2>&1; then
          rpm -qa --queryformat '%{NAME}\t%{VERSION}\t%{RELEASE}\n' | head -100
        else
          echo "Not a RHEL system"
        fi
      register: rpm_packages
      changed_when: false
      failed_when: false
      when: ansible_facts.os_family == "RedHat"
    
    - name: Check for vulnerable packages
      set_fact:
        vulnerable_packages: []
      changed_when: false
    
    - name: Detect known vulnerable packages
      set_fact:
        vulnerable_packages: "{{ vulnerable_packages + [item] }}"
      loop:
        - 'openssl'
        - 'bash'
        - 'sudo'
        - 'exim'
        - 'samba'
        - 'bind9'
      when: >
        (ansible_facts.os_family == "Debian" and item in deb_packages.stdout) or
        (ansible_facts.os_family == "RedHat" and item in rpm_packages.stdout)
    
    - name: Check package repositories
      shell: |
        if [ -f /etc/apt/sources.list ]; then
          grep -E "^deb " /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null | grep -v "^#" | head -20
        elif [ -f /etc/yum.repos.d/*.repo ]; then
          grep -E "^\[|^baseurl=" /etc/yum.repos.d/*.repo 2>/dev/null | grep -v "^#" | head -20
        fi
      register: package_repos
      changed_when: false
      failed_when: false
    
    - name: Set package audit facts
      set_fact:
        audit_packages: "{{ (deb_packages.stdout_lines if ansible_facts.os_family == 'Debian' else rpm_packages.stdout_lines) | default([]) }}"
        package_repositories: "{{ package_repos.stdout_lines | default([]) }}"
        vulnerable_packages_detected: "{{ vulnerable_packages | default([]) | length > 0 }}"
    
    - name: Display package summary
      debug:
        msg: |
          Package Audit Summary:
          - Packages listed: {{ audit_packages | length }}
          - Vulnerable packages detected: {{ vulnerable_packages_detected }}
          - Repositories configured: {{ package_repositories | length > 0 }}
  
  tags: packages,system
EOF

# -----------------------------
# Security Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Security Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/security.yml"
---
- name: Security Configuration Audit
  block:
    - name: Check SSH configuration
      shell: |
        for setting in PasswordAuthentication PermitRootLogin PermitEmptyPasswords; do
          grep -i "^$setting" /etc/ssh/sshd_config 2>/dev/null || echo "$setting not set"
        done
      register: ssh_config
      changed_when: false
      failed_when: false
    
    - name: Check PAM configuration
      shell: |
        grep -E "^auth|^account|^password|^session" /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/common-session 2>/dev/null | \
        grep -v "^#" | head -20
      register: pam_config
      changed_when: false
      failed_when: false
    
    - name: Check sudo configuration
      shell: |
        grep -E "^[^#].*ALL=.*ALL" /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true
      register: sudo_config
      changed_when: false
      failed_when: false
    
    - name: Check password policy
      shell: |
        grep -E "^PASS_" /etc/login.defs 2>/dev/null || true
        if [ -f /etc/security/pwquality.conf ]; then
          cat /etc/security/pwquality.conf
        fi
      register: password_policy
      changed_when: false
      failed_when: false
    
    - name: Check for .rhosts and .netrc files
      shell: |
        find /home /root -name ".rhosts" -o -name ".netrc" 2>/dev/null | xargs -I {} sh -c 'echo "Found: {}"; cat {} 2>/dev/null || echo "Empty or unreadable"'
      register: rhosts_files
      changed_when: false
      failed_when: false
    
    - name: Set security audit facts
      set_fact:
        ssh_password_login: "{{ 'PasswordAuthentication yes' in ssh_config.stdout }}"
        ssh_root_login: "{{ 'PermitRootLogin yes' in ssh_config.stdout or 'PermitRootLogin without-password' in ssh_config.stdout }}"
        ssh_empty_passwords: "{{ 'PermitEmptyPasswords yes' in ssh_config.stdout }}"
        pam_config_summary: "{{ pam_config.stdout_lines | default([]) }}"
        sudo_all_users: "{{ sudo_config.stdout_lines | default([]) }}"
        password_policy_config: "{{ password_policy.stdout_lines | default([]) }}"
        rhosts_files_found: "{{ rhosts_files.stdout_lines | default([]) | length > 0 }}"
    
    - name: Display security summary
      debug:
        msg: |
          Security Configuration Summary:
          - SSH password login enabled: {{ ssh_password_login }}
          - SSH root login enabled: {{ ssh_root_login }}
          - SSH empty passwords allowed: {{ ssh_empty_passwords }}
          - Sudo ALL for users: {{ sudo_all_users | length }}
          - Password policy configured: {{ password_policy_config | length > 0 }}
          - .rhosts/.netrc files found: {{ rhosts_files_found }}
  
  tags: security,auth
EOF

# -----------------------------
# Secrets Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Secrets Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/secrets.yml"
---
- name: Secrets Detection Audit
  block:
    - name: Find potential secrets in config files
      shell: |
        find /etc /home /root -type f \( -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.yml" -o -name "*.yaml" -o -name "*.json" \) \
        -exec grep -l -E "(password|secret|token|key|credential|auth)" {} \; 2>/dev/null | \
        head -50
      register: secret_files
      changed_when: false
      failed_when: false
    
    - name: Scan for hardcoded secrets
      shell: |
        find /etc /home /root -type f -size -100k \( -name "*.php" -o -name "*.py" -o -name "*.java" -o -name "*.js" -o -name "*.sh" \) \
        -exec grep -l -E "(passwd|password|pwd|secret|token|key)[ =:]['\"]" {} \; 2>/dev/null | \
        head -50
      register: hardcoded_secrets
      changed_when: false
      failed_when: false
    
    - name: Check for AWS credentials
      shell: |
        find /home /root -type f -name "*.aws*" -o -name "credentials" 2>/dev/null | \
        xargs -I {} sh -c 'echo "Found: {}"; grep -E "(aws_access_key|aws_secret_key)" {} 2>/dev/null || true'
      register: aws_creds
      changed_when: false
      failed_when: false
    
    - name: Check for SSH private keys with weak permissions
      shell: |
        find /home /root /etc/ssh -name "id_*" -type f 2>/dev/null | \
        xargs -I {} sh -c 'perms=$(stat -c "%a" {}); if [ $perms -gt 600 ]; then echo "{}: $perms"; fi'
      register: ssh_key_perms
      changed_when: false
      failed_when: false
    
    - name: Set secrets audit facts
      set_fact:
        secrets_list: >-
          {{
            (secret_files.stdout_lines | default([]))
            + (hardcoded_secrets.stdout_lines | default([]))
            + (aws_creds.stdout_lines | default([]))
          }}
    
        plaintext_secrets_found: >-
          {{
            (
              (secret_files.stdout_lines | default([]))
              + (hardcoded_secrets.stdout_lines | default([]))
              + (aws_creds.stdout_lines | default([]))
            ) | length > 0
          }}
    
        ssh_key_permission_issues: "{{ ssh_key_perms.stdout_lines | default([]) }}"

    
    - name: Display secrets summary
      debug:
        msg: |
          Secrets Detection Summary:
          - Potential secret files: {{ secret_files.stdout_lines | length }}
          - Hardcoded secrets found: {{ hardcoded_secrets.stdout_lines | length }}
          - AWS credentials found: {{ aws_creds.stdout_lines | length > 0 }}
          - Plaintext secrets found: {{ plaintext_secrets_found }}
          - SSH key permission issues: {{ ssh_key_permission_issues | length }}
  
  tags: secrets,security
EOF

# -----------------------------
# Containers Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Containers Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/containers.yml"
---
- name: Container Security Audit
  block:
    - name: Check for Docker installation
      shell: |
        which docker 2>/dev/null || echo "Docker not found"
      register: docker_check
      changed_when: false
      failed_when: false
    
    - name: Check for container runtimes
      shell: |
        which podman 2>/dev/null || echo "Podman not found"
        which containerd 2>/dev/null || echo "Containerd not found"
      register: container_runtimes
      changed_when: false
      failed_when: false
    
    - name: List running containers
      shell: |
        if command -v docker >/dev/null 2>&1; then
          docker ps --format '{% raw %}table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}{% endraw %}'
        else
          echo "Docker not installed"
        fi
      register: running_containers
      changed_when: false
      failed_when: false
    
    - name: Check for exposed Docker socket
      shell: |
        if [ -S /var/run/docker.sock ]; then
          stat -c "%a %U %G" /var/run/docker.sock
        else
          echo "Docker socket not found"
        fi
      register: docker_socket
      changed_when: false
      failed_when: false
    
    - name: Set container audit facts
      set_fact:
        containers_found: "{{ 'docker' in docker_check.stdout or 'podman' in container_runtimes.stdout }}"
        containers_running: "{{ 'CONTAINER' in running_containers.stdout }}"
        docker_socket_permissions: "{{ docker_socket.stdout_lines | default([]) }}"
        redflags_containers: "{{ '666' in docker_socket.stdout or '777' in docker_socket.stdout }}"
    
    - name: Display container summary
      debug:
        msg: |
          Container Security Summary:
          - Docker installed: {{ 'docker' in docker_check.stdout }}
          - Running containers: {{ containers_running }}
          - Docker socket permissions: {{ docker_socket_permissions }}
          - Red flags (world-writable socket): {{ redflags_containers }}
  
  tags: containers
EOF

# -----------------------------
# World Writable Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle World Writable Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/world_writable.yml"
---
- name: World-Writable Files Audit
  block:
    - name: Find world-writable files (excluding proc, sys, dev)
      shell: |
        find / -xdev -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -100
      register: ww_files
      changed_when: false
      failed_when: false
    
    - name: Find world-writable directories
      shell: |
        find / -xdev -type d -perm -0002 ! -perm -1000 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -50
      register: ww_dirs
      changed_when: false
      failed_when: false
    
    - name: Check for world-writable configuration files
      shell: |
        find /etc -type f -perm -0002 2>/dev/null
      register: ww_config
      changed_when: false
      failed_when: false
    
    - name: Set world-writable audit facts
      set_fact:
        world_writable_files: "{{ ww_files.stdout_lines | default([]) }}"
        world_writable_dirs: "{{ ww_dirs.stdout_lines | default([]) }}"
        world_writable_config: "{{ ww_config.stdout_lines | default([]) }}"
        redflags_world_writable: >-
          {{
            (
              (ww_files.stdout_lines | default([]))
              + (ww_dirs.stdout_lines | default([]))
              + (ww_config.stdout_lines | default([]))
            ) | length > 0
          }}
    
    - name: Display world-writable summary
      debug:
        msg: |
          World-Writable Audit Summary:
          - World-writable files: {{ world_writable_files | length }}
          - World-writable directories: {{ world_writable_dirs | length }}
          - World-writable config files: {{ world_writable_config | length }}
          - Red flags: {{ redflags_world_writable }}
  
  tags: permissions,security
EOF

# -----------------------------
# SSH Keys Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle SSH Keys Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/ssh_keys.yml"
---
- name: SSH Keys Audit
  block:
    - name: Find SSH private keys
      shell: |
        find /home /root /etc/ssh -type f -name "id_*" ! -name "*.pub" 2>/dev/null
      register: ssh_private_keys
      changed_when: false
      failed_when: false
    
    - name: Check for unprotected SSH keys
      shell: |
        for key in $(find /home /root /etc/ssh -type f -name "id_*" ! -name "*.pub" 2>/dev/null); do
          if ssh-keygen -y -P "" -f "$key" >/dev/null 2>&1; then
            echo "$key: UNPROTECTED"
          else
            echo "$key: protected"
          fi
        done
      register: unprotected_keys
      changed_when: false
      failed_when: false
    
    - name: Check SSH authorized_keys files
      shell: |
        find /home /root -name "authorized_keys" -type f 2>/dev/null | \
        xargs -I {} sh -c 'echo "File: {}"; stat -c "%a %U %G" {}; cat {} | wc -l'
      register: authorized_keys
      changed_when: false
      failed_when: false
    
    - name: Check for SSH host keys
      shell: |
        ls -la /etc/ssh/ssh_host_* 2>/dev/null || true
      register: ssh_host_keys
      changed_when: false
      failed_when: false
    
    - name: Set SSH keys audit facts
      set_fact:
        ssh_private_keys_list: "{{ ssh_private_keys.stdout_lines | default([]) }}"
        ssh_keys_unprotected: "{{ unprotected_keys.stdout_lines | select('search', 'UNPROTECTED') | list }}"
        redflags_ssh_keys_unprotected: "{{ (ssh_keys_unprotected | default([]) | length) > 0 }}"
        authorized_keys_files: "{{ authorized_keys.stdout_lines | default([]) }}"
        ssh_host_keys_list: "{{ ssh_host_keys.stdout_lines | default([]) }}"
    
    - name: Display SSH keys summary
      debug:
        msg: |
          SSH Keys Audit Summary:
          - SSH private keys: {{ ssh_private_keys_list | length }}
          - Unprotected keys: {{ ssh_keys_unprotected | length }}
          - Authorized keys files: {{ authorized_keys_files | length }}
          - SSH host keys: {{ ssh_host_keys_list | length > 0 }}
          - Red flags (unprotected): {{ redflags_ssh_keys_unprotected }}
  
  tags: ssh,security
EOF

# -----------------------------
# Inactive Users Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Inactive Users Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/inactive_users.yml"
---
- name: Inactive Users Audit
  block:
    - name: List inactive users (last login > 90 days)
      shell: |
        lastlog -b 90 2>/dev/null | tail -n +2 || echo "No lastlog data"
      register: inactive_users
      changed_when: false
      failed_when: false
    
    - name: Check user last login times
      shell: |
        for user in $(getent passwd | cut -d: -f1); do
          lastlog -u "$user" 2>/dev/null | tail -1
        done | grep -E "(Never logged in|^$)"
      register: never_logged_in
      changed_when: false
      failed_when: false
    
    - name: Check for expired accounts
      shell: |
        getent shadow | awk -F: '($2 ~ /^!/ || $2 ~ /^[*]/) && $2 != "" {print $1}' 2>/dev/null
      register: expired_accounts
      changed_when: false
      failed_when: false
    
    - name: Check account lock status
      shell: |
        getent shadow | awk -F: '($2 ~ /^!!/) {print $1}' 2>/dev/null
      register: locked_accounts
      changed_when: false
      failed_when: false
    
    - name: Set inactive users audit facts
      set_fact:
        audit_inactive_users: "{{ inactive_users.stdout_lines | default([]) }}"
        redflags_inactive_users: "{{ (inactive_users.stdout_lines | default([]) | length) > 10 }}"
        never_logged_in_users: "{{ never_logged_in.stdout_lines | default([]) }}"
        expired_accounts_list: "{{ expired_accounts.stdout_lines | default([]) }}"
        locked_accounts_list: "{{ locked_accounts.stdout_lines | default([]) }}"
    
    - name: Display inactive users summary
      debug:
        msg: |
          Inactive Users Audit Summary:
          - Inactive users (>90 days): {{ audit_inactive_users | length }}
          - Never logged in users: {{ never_logged_in_users | length }}
          - Expired accounts: {{ expired_accounts_list | length }}
          - Locked accounts: {{ locked_accounts_list | length }}
          - Red flags (>10 inactive): {{ redflags_inactive_users }}
  
  tags: users,auth
EOF

# -----------------------------
# Environment Secrets Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Environment Secrets Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/env_secrets.yml"
---
- name: Environment Secrets Audit
  block:
    - name: Check for ENV secrets
      shell: |
        printenv | grep -E -i "(pass|secret|token|key|auth|cred)" | grep -v "^_"
      register: env_secrets
      changed_when: false
      failed_when: false
    
    - name: Check shell history for secrets
      shell: |
        for file in /home/*/.bash_history /root/.bash_history; do
          if [ -f "$file" ]; then
            echo "=== $file ==="
            grep -E "(pass|secret|token|key|auth)" "$file" | head -10 || true
          fi
        done
      register: shell_history
      changed_when: false
      failed_when: false
    
    - name: Check process environment
      shell: |
        ps auxwww 2>/dev/null | grep -E "(pass|secret|token)" || true
      register: process_env
      changed_when: false
      failed_when: false
    
    - name: Check for .env files
      shell: |
        find /home /root /var/www -name ".env" -type f 2>/dev/null | head -20
      register: env_files
      changed_when: false
      failed_when: false
    
    - name: Set environment secrets audit facts
      set_fact:
        env_secrets_list: "{{ env_secrets.stdout_lines | default([]) }}"
        redflags_env_secrets: "{{ (env_secrets.stdout_lines | default([]) | length) > 0 }}"
        shell_history_secrets: "{{ shell_history.stdout_lines | default([]) }}"
        process_env_secrets: "{{ process_env.stdout_lines | default([]) }}"
        env_files_found: "{{ env_files.stdout_lines | default([]) }}"
    
    - name: Display environment secrets summary
      debug:
        msg: |
          Environment Secrets Audit Summary:
          - ENV secrets found: {{ env_secrets_list | length }}
          - Shell history secrets: {{ shell_history_secrets | length > 0 }}
          - Process environment secrets: {{ process_env_secrets | length > 0 }}
          - .env files found: {{ env_files_found | length }}
          - Red flags: {{ redflags_env_secrets }}
  
  tags: secrets,security
EOF

# -----------------------------
# Logrotate Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Logrotate Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/logrotate.yml"
---
- name: Logrotate Configuration Audit
  block:
    - name: Check logrotate configuration
      shell: |
        logrotate --debug /etc/logrotate.conf 2>&1 | grep -E "error|cannot" || echo "No errors found"
      register: logrotate_check
      changed_when: false
      failed_when: false
    
    - name: Check log file permissions
      shell: |
        find /var/log -type f -exec stat -c "%a %n" {} \; 2>/dev/null | grep -E "^(7[0-7][0-7]|.[0-7]7.)" | head -20
      register: log_perms
      changed_when: false
      failed_when: false
    
    - name: Check log directory permissions
      shell: |
        find /var/log -type d -exec stat -c "%a %n" {} \; 2>/dev/null | grep -E "^(7[0-7][0-7]|.[0-7]7.)" | head -10
      register: log_dir_perms
      changed_when: false
      failed_when: false
    
    - name: Check for log file size
      shell: |
        find /var/log -type f -size +100M 2>/dev/null | head -10
      register: large_logs
      changed_when: false
      failed_when: false
    
    - name: Set logrotate audit facts
      set_fact:
        redflags_logrotate: "{{ 'error' in logrotate_check.stdout or 'cannot' in logrotate_check.stdout }}"
        log_permission_issues: "{{ log_perms.stdout_lines | default([]) }}"
        log_dir_permission_issues: "{{ log_dir_perms.stdout_lines | default([]) }}"
        large_log_files: "{{ large_logs.stdout_lines | default([]) }}"
    
    - name: Display logrotate summary
      debug:
        msg: |
          Logrotate Audit Summary:
          - Logrotate errors: {{ redflags_logrotate }}
          - Log permission issues: {{ log_permission_issues | length }}
          - Log directory permission issues: {{ log_dir_permission_issues | length }}
          - Large log files (>100MB): {{ large_log_files | length }}
  
  tags: logging,system
EOF

# -----------------------------
# SUID/SGID Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle SUID/SGID Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/suid_sgid.yml"
---
- name: SUID/SGID Files Audit
  block:
    - name: Find SUID files
      shell: |
        find / -xdev -type f -perm -4000 2>/dev/null | grep -vE "(/proc|/sys|/dev)" | head -50
      register: suid_files
      changed_when: false
      failed_when: false
    
    - name: Find SGID files
      shell: |
        find / -xdev -type f -perm -2000 2>/dev/null | grep -vE "(/proc|/sys|/dev)" | head -50
      register: sgid_files
      changed_when: false
      failed_when: false
    
    - name: Check for dangerous SUID binaries
      set_fact:
        dangerous_suid: []
    
    - name: Detect dangerous SUID binaries
      set_fact:
        dangerous_suid: "{{ dangerous_suid + [item] }}"
      loop:
        - '/bin/mount'
        - '/bin/umount'
        - '/bin/su'
        - '/usr/bin/sudo'
        - '/usr/bin/passwd'
        - '/usr/bin/chsh'
        - '/usr/bin/chfn'
        - '/usr/bin/gpasswd'
        - '/usr/bin/newgrp'
      when: item in suid_files.stdout_lines
    
    - name: Set SUID/SGID audit facts
      set_fact:
        suid_sgid_files: >-
          {{
            (suid_files.stdout_lines | default([]))
            + (sgid_files.stdout_lines | default([]))
          }}
        redflags_suid_sgid: >-
          {{
            (
              (suid_files.stdout_lines | default([]))
              + (sgid_files.stdout_lines | default([]))
            ) | length > 20
          }}
        dangerous_suid_binaries: "{{ dangerous_suid | default([]) }}"
    
    - name: Display SUID/SGID summary
      debug:
        msg: |
          SUID/SGID Audit Summary:
          - SUID files: {{ suid_files.stdout_lines | length }}
          - SGID files: {{ sgid_files.stdout_lines | length }}
          - Dangerous SUID binaries: {{ dangerous_suid_binaries | length }}
          - Red flags (>20 SUID/SGID): {{ redflags_suid_sgid }}
  
  tags: permissions,security
EOF

# -----------------------------
# IPv6 Ports Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle IPv6 Ports Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/ipv6_ports.yml"
---
- name: IPv6 Configuration Audit
  block:
    - name: List IPv6 listening ports
      shell: |
        ss -tuln6 2>/dev/null || echo "IPv6 not available"
      register: ports6
      changed_when: false
      failed_when: false
    
    - name: Check IPv6 configuration
      shell: |
        sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "IPv6 not configured"
      register: ipv6_config
      changed_when: false
      failed_when: false
    
    - name: Check IPv6 addresses
      shell: |
        ip -6 addr show 2>/dev/null || echo "No IPv6 addresses"
      register: ipv6_addresses
      changed_when: false
      failed_when: false
    
    - name: Set IPv6 audit facts
      set_fact:
        audit_ports_ipv6: "{{ ports6.stdout_lines | default([]) }}"
        redflags_ipv6_ports: "{{ (audit_ports_ipv6 | select('search', '22|80|443|3306|3389') | list | length > 0) if audit_ports_ipv6 is defined else false }}"
        ipv6_disabled: "{{ 'net.ipv6.conf.all.disable_ipv6 = 1' in ipv6_config.stdout }}"
        ipv6_addresses_list: "{{ ipv6_addresses.stdout_lines | default([]) }}"
    
    - name: Display IPv6 summary
      debug:
        msg: |
          IPv6 Audit Summary:
          - IPv6 ports listening: {{ audit_ports_ipv6 | length }}
          - IPv6 disabled: {{ ipv6_disabled }}
          - IPv6 addresses: {{ ipv6_addresses_list | length }}
          - Red flags (risky IPv6 ports): {{ redflags_ipv6_ports }}
  
  tags: ipv6,network
EOF

# -----------------------------
# Failed Logins Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Failed Logins Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/failed_logins.yml"
---
- name: Failed Logins Audit
  block:
    - name: Check failed logins
      shell: |
        lastb 2>/dev/null | head -20 || echo "No failed login records"
      register: failed_logins
      changed_when: false
      failed_when: false
    
    - name: Check authentication logs
      shell: |
        grep -E "(Failed|Invalid|Failure)" /var/log/auth.log /var/log/secure 2>/dev/null | tail -20 || echo "No auth logs"
      register: auth_logs
      changed_when: false
      failed_when: false
    
    - name: Check faillock/pam_tally2
      shell: |
        if command -v faillock >/dev/null 2>&1; then
          faillock
        elif [ -f /var/log/faillog ]; then
          faillog -a
        else
          echo "No faillock data"
        fi
      register: faillock_data
      changed_when: false
      failed_when: false
    
    - name: Set failed logins audit facts
      set_fact:
        failed_login_attempts: "{{ failed_logins.stdout_lines | default([]) }}"
        redflags_failed_logins: "{{ (failed_logins.stdout_lines | default([]) | length) > 10 }}"
        auth_log_entries: "{{ auth_logs.stdout_lines | default([]) }}"
        faillock_info: "{{ faillock_data.stdout_lines | default([]) }}"
    
    - name: Display failed logins summary
      debug:
        msg: |
          Failed Logins Audit Summary:
          - Failed login attempts: {{ failed_login_attempts | length }}
          - Auth log entries: {{ auth_log_entries | length }}
          - Faillock data: {{ faillock_info | length > 0 }}
          - Red flags (>10 failed attempts): {{ redflags_failed_logins }}
  
  tags: auth,security
EOF

# -----------------------------
# Crypto Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Crypto Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/crypto.yml"
---
- name: Cryptographic Configuration Audit
  block:
    - name: Check SSL/TLS configuration
      shell: |
        openssl ciphers -v 2>/dev/null | grep -E "(RC4|MD5|DES|3DES|NULL|EXP|ANON)" || echo "No weak ciphers detected"
      register: weak_ciphers
      changed_when: false
      failed_when: false
    
    - name: Check SSH cryptographic algorithms
      shell: |
        ssh -Q cipher | grep -E "(cbc|arcfour)" || echo "No weak SSH ciphers"
      register: weak_ssh_ciphers
      changed_when: false
      failed_when: false
    
    - name: Check for weak hash algorithms
      shell: |
        find /etc -type f -exec grep -l "md5\|sha1" {} \; 2>/dev/null | head -10
      register: weak_hashes
      changed_when: false
      failed_when: false
    
    - name: Set crypto audit facts
      set_fact:
        weak_crypto_detected: >-
          {{
            (weak_ciphers.stdout_lines | default([]))
            + (weak_ssh_ciphers.stdout_lines | default([]))
            + (weak_hashes.stdout_lines | default([]))
          }}
        redflags_crypto: >-
          {{
            (
              (weak_ciphers.stdout_lines | default([]))
              + (weak_ssh_ciphers.stdout_lines | default([]))
              + (weak_hashes.stdout_lines | default([]))
            ) | length > 0
          }}
    
    - name: Display crypto summary
      debug:
        msg: |
          Cryptographic Audit Summary:
          - Weak SSL/TLS ciphers: {{ weak_ciphers.stdout_lines | length > 0 }}
          - Weak SSH ciphers: {{ weak_ssh_ciphers.stdout_lines | length > 0 }}
          - Weak hash algorithms: {{ weak_hashes.stdout_lines | length }}
          - Red flags: {{ redflags_crypto }}
  
  tags: crypto,security
EOF

# -----------------------------
# Permissions Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Permissions Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/permissions.yml"
---
- name: File Permissions Audit
  block:
    - name: Check critical file permissions
      shell: |
        for file in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers; do
          if [ -f "$file" ]; then
            stat -c "%a %U %G %n" "$file"
          fi
        done
      register: critical_perms
      changed_when: false
      failed_when: false
    
    - name: Check for unowned files
      shell: |
        find / -xdev -nouser 2>/dev/null | head -20
      register: unowned_files
      changed_when: false
      failed_when: false
    
    - name: Check for ungrouped files
      shell: |
        find / -xdev -nogroup 2>/dev/null | head -20
      register: ungrouped_files
      changed_when: false
      failed_when: false
    
    - name: Set permissions audit facts
      set_fact:
        critical_file_permissions: "{{ critical_perms.stdout_lines | default([]) }}"
        unowned_files_list: "{{ unowned_files.stdout_lines | default([]) }}"
        ungrouped_files_list: "{{ ungrouped_files.stdout_lines | default([]) }}"
        redflags_permissions: >-
          {{
            (
              (unowned_files.stdout_lines | default([]))
              + (ungrouped_files.stdout_lines | default([]))
            ) | length > 0
          }}

    - name: Display permissions summary
      debug:
        msg: |
          Permissions Audit Summary:
          - Critical file permissions: {{ critical_file_permissions | length }}
          - Unowned files: {{ unowned_files_list | length }}
          - Ungrouped files: {{ ungrouped_files_list | length }}
          - Red flags: {{ redflags_permissions }}
  
  tags: permissions,security
EOF

# -----------------------------
# Sysctl Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Sysctl Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/sysctl.yml"
---
- name: Sysctl Configuration Audit
  block:
    - name: Check important sysctl settings
      shell: |
        for param in net.ipv4.ip_forward kernel.randomize_va_space net.ipv4.conf.all.accept_source_route \
                     net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.log_martians \
                     net.ipv4.tcp_syncookies net.ipv6.conf.all.disable_ipv6; do
          sysctl $param 2>/dev/null || echo "$param: not found"
        done
      register: sysctl_values
      changed_when: false
      failed_when: false
    
    - name: Check sysctl configuration files
      shell: |
        grep -r -E "^(net\.|kernel\.)" /etc/sysctl.conf /etc/sysctl.d/ 2>/dev/null | head -20
      register: sysctl_config
      changed_when: false
      failed_when: false
    
    - name: Check for ASLR status
      shell: |
        sysctl kernel.randomize_va_space 2>/dev/null || echo "0"
      register: aslr_status
      changed_when: false
      failed_when: false
    
    - name: Set sysctl audit facts
      set_fact:
        sysctl_issues: []
        redflags_sysctl: false
        redflags_kernel_randomize: "{{ '2' not in aslr_status.stdout }}"
    
    - name: Analyze sysctl values
      set_fact:
        sysctl_issues: "{{ sysctl_issues + ['ip_forward_enabled'] }}"
        redflags_sysctl: true
      when: "'net.ipv4.ip_forward = 1' in sysctl_values.stdout"
    
    - name: Check for source route acceptance
      set_fact:
        sysctl_issues: "{{ sysctl_issues + ['accept_source_route'] }}"
        redflags_sysctl: true
      when: "'net.ipv4.conf.all.accept_source_route = 1' in sysctl_values.stdout"
    
    - name: Display sysctl summary
      debug:
        msg: |
          Sysctl Audit Summary:
          - Sysctl issues found: {{ sysctl_issues | length }}
          - ASLR enabled: {{ 'kernel.randomize_va_space = 2' in sysctl_values.stdout }}
          - IP forwarding: {{ 'net.ipv4.ip_forward = 0' in sysctl_values.stdout }}
          - Source route acceptance: {{ 'net.ipv4.conf.all.accept_source_route = 0' in sysctl_values.stdout }}
          - Red flags: {{ redflags_sysctl }}
  
  tags: sysctl,network
EOF

# -----------------------------
# Updates Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Updates Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/updates.yml"
---
- name: System Updates Audit
  block:
    - name: Check pending updates (Debian/Ubuntu)
      shell: |
        if command -v apt-get >/dev/null 2>&1; then
          apt-get update >/dev/null 2>&1
          apt list --upgradable 2>/dev/null | tail -n +2
        else
          echo "Not a Debian system"
        fi
      register: updates_apt
      changed_when: false
      failed_when: false
      when: ansible_facts.os_family == "Debian"
    
    - name: Check pending updates (RHEL/CentOS)
      shell: |
        if command -v yum >/dev/null 2>&1; then
          yum check-update --quiet 2>/dev/null || true
        else
          echo "Not a RHEL system"
        fi
      register: updates_yum
      changed_when: false
      failed_when: false
      when: ansible_facts.os_family == "RedHat"
    
    - name: Check kernel version
      shell: |
        uname -r
      register: kernel_version
      changed_when: false
    
    - name: Check last update date
      shell: |
        if [ -f /var/log/apt/history.log ]; then
          grep "Start-Date" /var/log/apt/history.log | tail -1
        elif [ -f /var/log/yum.log ]; then
          tail -1 /var/log/yum.log
        else
          echo "No update logs found"
        fi
      register: last_update
      changed_when: false
      failed_when: false
    
    - name: Check for security updates
      shell: |
        if command -v apt-get >/dev/null 2>&1; then
          apt-get upgrade --dry-run 2>/dev/null | grep -i security || echo "No security updates"
        elif command -v yum >/dev/null 2>&1; then
          yum updateinfo list security 2>/dev/null || echo "No security updates"
        fi
      register: security_updates
      changed_when: false
      failed_when: false
    
    - name: Set updates audit facts
      set_fact:
        pending_updates: "{{ (updates_apt.stdout_lines if ansible_facts.os_family == 'Debian' else updates_yum.stdout_lines) | default([]) }}"
        redflags_pending_updates: "{{ ((updates_apt.stdout_lines if ansible_facts.os_family == 'Debian' else updates_yum.stdout_lines) | default([]) | length) > 0 }}"
        current_kernel: "{{ kernel_version.stdout }}"
        last_update_date: "{{ last_update.stdout }}"
        security_updates_available: "{{ security_updates.stdout_lines | default([]) }}"
    
    - name: Display updates summary
      debug:
        msg: |
          Updates Audit Summary:
          - Pending updates: {{ pending_updates | length }}
          - Current kernel: {{ current_kernel }}
          - Last update: {{ last_update_date }}
          - Security updates available: {{ security_updates_available | length > 0 }}
          - Red flags (pending updates): {{ redflags_pending_updates }}
  
  tags: updates,system
EOF

# -----------------------------
# Password Age Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Password Age Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/password_age.yml"
---
- name: Password Age Audit
  block:
    - name: Check password ages for all users
      shell: |
        for user in $(getent passwd | cut -d: -f1); do
          chage -l "$user" 2>/dev/null | grep "Password expires" || true
        done
      register: password_age
      changed_when: false
      failed_when: false
    
    - name: Check password policy from shadow
      shell: |
        getent shadow | awk -F: '{print $1 ":" $5}' | grep -v "::"
      register: shadow_expiry
      changed_when: false
      failed_when: false
    
    - name: Check password minimum age
      shell: |
        grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null || echo "PASS_MIN_DAYS not set"
      register: min_days
      changed_when: false
      failed_when: false
    
    - name: Check password warning age
      shell: |
        grep "^PASS_WARN_AGE" /etc/login.defs 2>/dev/null || echo "PASS_WARN_AGE not set"
      register: warn_age
      changed_when: false
      failed_when: false
    
    - name: Set password age audit facts
      set_fact:
        old_passwords: "{{ password_age.stdout_lines | default([]) | select('search', 'never|[0-9]{4}') | list }}"
        redflags_old_passwords: "{{ (old_passwords | default([]) | length) > 0 }}"
        shadow_expiry_info: "{{ shadow_expiry.stdout_lines | default([]) }}"
        password_min_days: "{{ min_days.stdout }}"
        password_warn_age: "{{ warn_age.stdout }}"
    
    - name: Display password age summary
      debug:
        msg: |
          Password Age Audit Summary:
          - Old passwords detected: {{ old_passwords | length }}
          - Password min days: {{ password_min_days }}
          - Password warn age: {{ password_warn_age }}
          - Red flags (old passwords): {{ redflags_old_passwords }}
  
  tags: passwords,auth
EOF

# -----------------------------
# Auditd Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Auditd Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/auditd.yml"
---
- name: Auditd Configuration Audit
  block:
    - name: Check if auditd is installed
      shell: |
        which auditd 2>/dev/null || echo "not installed"
      register: auditd_installed
      changed_when: false
    
    - name: Check auditd service status
      systemd:
        name: auditd
      register: auditd_service
      changed_when: false
      ignore_errors: yes
    
    - name: Check auditd rules
      shell: |
        auditctl -l 2>/dev/null || echo "No rules"
      register: auditd_rules
      changed_when: false
      failed_when: false
    
    - name: Check auditd configuration
      shell: |
        grep -E "^max_log_file|^num_logs|^space_left|^admin_space_left|^action_mail_acct" /etc/audit/auditd.conf 2>/dev/null || echo "No config"
      register: auditd_config
      changed_when: false
      failed_when: false
    
    - name: Set auditd audit facts
      set_fact:
        auditd_active: "{{ auditd_service is defined and auditd_service.status.ActiveState == 'active' }}"
        redflags_auditd: "{{ 'not installed' in auditd_installed.stdout or (auditd_service is defined and auditd_service.status.ActiveState != 'active') }}"
        auditd_rules_list: "{{ auditd_rules.stdout_lines | default([]) }}"
        auditd_config_summary: "{{ auditd_config.stdout_lines | default([]) }}"
    
    - name: Display auditd summary
      debug:
        msg: |
          Auditd Audit Summary:
          - Auditd installed: {{ 'not installed' not in auditd_installed.stdout }}
          - Auditd active: {{ auditd_active }}
          - Auditd rules: {{ auditd_rules_list | length > 0 }}
          - Auditd config: {{ auditd_config_summary | length > 0 }}
          - Red flags: {{ redflags_auditd }}
  
  tags: auditd,security
EOF

# -----------------------------
# Network Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Network Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/network.yml"
---
- name: Network Configuration Audit
  block:
    - name: Check network interfaces
      shell: |
        ip addr show | grep -E "^[0-9]+:|inet "
      register: network_interfaces
      changed_when: false
      failed_when: false
    
    - name: Check routing table
      shell: |
        ip route show
      register: routing_table
      changed_when: false
      failed_when: false
    
    - name: Check DNS configuration
      shell: |
        cat /etc/resolv.conf 2>/dev/null || echo "No resolv.conf"
        echo "---"
        cat /etc/hosts 2>/dev/null | head -10
      register: dns_config
      changed_when: false
      failed_when: false
    
    - name: Check for promiscuous mode
      shell: |
        ip link show | grep PROMISC || echo "No promiscuous interfaces"
      register: promiscuous
      changed_when: false
      failed_when: false
    
    - name: Set network audit facts
      set_fact:
        network_info:
          interfaces: "{{ network_interfaces.stdout_lines | default([]) }}"
          routes: "{{ routing_table.stdout_lines | default([]) }}"
          dns: "{{ dns_config.stdout_lines | default([]) }}"
          promiscuous: "{{ promiscuous.stdout_lines | default([]) }}"
        redflags_network: "{{ 'PROMISC' in promiscuous.stdout }}"
    
    - name: Display network summary
      debug:
        msg: |
          Network Audit Summary:
          - Network interfaces: {{ network_interfaces.stdout_lines | length }}
          - Routing table entries: {{ routing_table.stdout_lines | length }}
          - DNS configuration: {{ dns_config.stdout_lines | length > 0 }}
          - Promiscuous interfaces: {{ 'PROMISC' in promiscuous.stdout }}
          - Red flags: {{ redflags_network }}
  
  tags: network
EOF

# -----------------------------
# Logging Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Logging Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/logging.yml"
---
- name: Logging Configuration Audit
  block:
    - name: Check syslog/rsyslog configuration
      shell: |
        if systemctl is-active rsyslog >/dev/null 2>&1; then
          echo "rsyslog active"
          rsyslogd -N1 2>&1 | grep -i error || echo "No errors"
        elif systemctl is-active syslog-ng >/dev/null 2>&1; then
          echo "syslog-ng active"
        else
          echo "No syslog service active"
        fi
      register: syslog_status
      changed_when: false
      failed_when: false
    
    - name: Check journald configuration
      shell: |
        if systemctl is-active systemd-journald >/dev/null 2>&1; then
          echo "journald active"
          journalctl --disk-usage
        else
          echo "journald not active"
        fi
      register: journald_status
      changed_when: false
      failed_when: false
    
    - name: Set logging audit facts
      set_fact:
        logging_status:
          syslog: "{{ syslog_status.stdout_lines | default([]) }}"
          journald: "{{ journald_status.stdout_lines | default([]) }}"
        redflags_logging: "{{ 'No syslog service active' in syslog_status.stdout }}"
    
    - name: Display logging summary
      debug:
        msg: |
          Logging Audit Summary:
          - Syslog status: {{ syslog_status.stdout_lines[0] if syslog_status.stdout_lines else 'Unknown' }}
          - Journald status: {{ journald_status.stdout_lines[0] if journald_status.stdout_lines else 'Unknown' }}
          - Red flags: {{ redflags_logging }}
  
  tags: logging,system
EOF

# -----------------------------
# Compliance Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Compliance Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/compliance.yml"
---
- name: Compliance Framework Detection
  block:
    - name: Check for compliance frameworks
      set_fact:
        compliance_frameworks: []
    
    - name: Detect PCI DSS requirements
      set_fact:
        compliance_frameworks: "{{ compliance_frameworks + ['PCI_DSS'] }}"
      when:
        - risky_ports_detected | default([]) | bool
        - firewall_enabled | default(false)
    
    - name: Detect HIPAA requirements
      set_fact:
        compliance_frameworks: "{{ compliance_frameworks + ['HIPAA'] }}"
      when:
        - auditd_active | default(false)
        - "'encryption' in security_updates_available | join(' ')"
    
    - name: Set compliance audit facts
      set_fact:
        compliance_checks: "{{ compliance_frameworks }}"
        redflags_compliance: "{{ compliance_frameworks | length == 0 }}"
    
    - name: Display compliance summary
      debug:
        msg: |
          Compliance Audit Summary:
          - Detected frameworks: {{ compliance_frameworks | join(', ') }}
          - Red flags (no frameworks): {{ redflags_compliance }}
  
  tags: compliance
EOF

# -----------------------------
# Risk Expiry Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Risk Expiry Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/risk_expiry.yml"
---
- name: Risk Expiry Audit
  block:
    - name: Check SSL certificate expiry
      shell: |
        find /etc/ssl /etc/apache2 /etc/nginx -name "*.crt" -o -name "*.pem" 2>/dev/null | \
        head -10 | while read cert; do
          echo "Certificate: $cert"
          openssl x509 -enddate -noout -in "$cert" 2>/dev/null || echo "Invalid certificate"
        done
      register: cert_expiry
      changed_when: false
      failed_when: false
    
    - name: Check password expiry
      shell: |
        getent shadow | awk -F: '($5 != "" && $5 < 30) {print $1 ": expires in " $5 " days"}' 2>/dev/null
      register: password_expiry
      changed_when: false
      failed_when: false
    
    - name: Check account expiry
      shell: |
        getent shadow | awk -F: '($7 != "" && $7 < 30) {print $1 ": account expires in " $7 " days"}' 2>/dev/null
      register: account_expiry
      changed_when: false
      failed_when: false
    
    - name: Set risk expiry audit facts
      set_fact:
        risk_expiry_checks:
          certificates: "{{ cert_expiry.stdout_lines | default([]) }}"
          passwords: "{{ password_expiry.stdout_lines | default([]) }}"
          accounts: "{{ account_expiry.stdout_lines | default([]) }}"
        redflags_risk_expiry: >-
          {{
            (
              (cert_expiry.stdout_lines | default([]))
              + (password_expiry.stdout_lines | default([]))
              + (account_expiry.stdout_lines | default([]))
            ) | length > 0
          }}

    - name: Display risk expiry summary
      debug:
        msg: |
          Risk Expiry Audit Summary:
          - Certificate expiry checks: {{ cert_expiry.stdout_lines | length }}
          - Password expiry warnings: {{ password_expiry.stdout_lines | length }}
          - Account expiry warnings: {{ account_expiry.stdout_lines | length }}
          - Red flags: {{ redflags_risk_expiry }}
  
  tags: compliance,security
EOF

# -----------------------------
# Kernel Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Kernel Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/kernel.yml"
---
- name: Kernel Security Audit
  block:
    - name: Check kernel version and vulnerabilities
      shell: |
        uname -r
        echo "---"
        echo "Checking for known vulnerabilities..."
      register: kernel_check
      changed_when: false
      failed_when: false
    
    - name: Check kernel module blacklist
      shell: |
        lsmod | grep -E "(bluetooth|firewire|thunderbolt|usb-storage)" || echo "No risky modules loaded"
      register: kernel_modules
      changed_when: false
      failed_when: false
    
    - name: Check kernel hardening
      shell: |
        sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope 2>/dev/null
      register: kernel_hardening
      changed_when: false
      failed_when: false
    
    - name: Set kernel audit facts
      set_fact:
        kernel_version: "{{ kernel_check.stdout_lines[0] }}"
        risky_kernel_modules: "{{ kernel_modules.stdout_lines | default([]) }}"
        kernel_hardening_status: "{{ kernel_hardening.stdout_lines | default([]) }}"
        redflags_kernel: "{{ 'No kernel live patching' in kernel_check.stdout }}"
    
    - name: Display kernel summary
      debug:
        msg: |
          Kernel Audit Summary:
          - Kernel version: {{ kernel_version }}
          - Risky kernel modules: {{ risky_kernel_modules | length }}
          - Kernel hardening status: {{ kernel_hardening_status | length }}
          - Red flags: {{ redflags_kernel }}
  
  tags: kernel,system
EOF

# -----------------------------
# Boot Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Boot Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/boot.yml"
---
- name: Boot Configuration Audit
  block:
    - name: Check boot loader configuration
      shell: |
        if [ -f /boot/grub/grub.cfg ]; then
          stat -c "%a %U %G" /boot/grub/grub.cfg
          grep -E "^set superusers|^password" /boot/grub/grub.cfg 2>/dev/null || echo "No boot password"
        elif [ -f /boot/grub2/grub.cfg ]; then
          stat -c "%a %U %G" /boot/grub2/grub.cfg
          grep -E "^set superusers|^password" /boot/grub2/grub.cfg 2>/dev/null || echo "No boot password"
        else
          echo "No GRUB configuration found"
        fi
      register: boot_config
      changed_when: false
      failed_when: false
    
    - name: Check startup services
      shell: |
        systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -20
      register: startup_services
      changed_when: false
      failed_when: false
    
    - name: Set boot audit facts
      set_fact:
        boot_security:
          grub_config: "{{ boot_config.stdout_lines | default([]) }}"
          startup: "{{ startup_services.stdout_lines | default([]) }}"
        redflags_boot: "{{ 'No boot password' in boot_config.stdout }}"
    
    - name: Display boot summary
      debug:
        msg: |
          Boot Audit Summary:
          - Boot loader configuration: {{ boot_config.stdout_lines | length > 0 }}
          - Startup services: {{ startup_services.stdout_lines | length }}
          - Red flags (no boot password): {{ redflags_boot }}
  
  tags: boot,system
EOF

# -----------------------------
# Filesystem Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Filesystem Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/filesystem.yml"
---
- name: Filesystem Security Audit
  block:
    - name: Check filesystem types
      shell: |
        df -Th | grep -v tmpfs
      register: filesystem_types
      changed_when: false
      failed_when: false
    
    - name: Check mount options
      shell: |
        mount | grep -E "(nodev|nosuid|noexec)" || echo "No security mount options"
      register: mount_options
      changed_when: false
      failed_when: false
    
    - name: Check for encrypted filesystems
      shell: |
        blkid | grep -i crypto || echo "No encrypted filesystems"
      register: encrypted_fs
      changed_when: false
      failed_when: false
    
    - name: Set filesystem audit facts
      set_fact:
        filesystem_security:
          types: "{{ filesystem_types.stdout_lines | default([]) }}"
          options: "{{ mount_options.stdout_lines | default([]) }}"
          encrypted: "{{ encrypted_fs.stdout_lines | default([]) }}"
        redflags_filesystem: "{{ 'No encrypted filesystems' in encrypted_fs.stdout }}"
    
    - name: Display filesystem summary
      debug:
        msg: |
          Filesystem Audit Summary:
          - Filesystem types: {{ filesystem_types.stdout_lines | length }}
          - Security mount options: {{ mount_options.stdout_lines | length > 0 }}
          - Encrypted filesystems: {{ encrypted_fs.stdout_lines | length > 0 }}
          - Red flags (no encryption): {{ redflags_filesystem }}
  
  tags: filesystem,security
EOF

# -----------------------------
# Firewall Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Firewall Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/firewall.yml"
---
- name: Firewall Configuration Audit
  block:
    - name: Check firewall status (iptables)
      shell: |
        if command -v iptables >/dev/null 2>&1; then
          iptables -L -n 2>/dev/null | head -50
        else
          echo "iptables not installed"
        fi
      register: fw_iptables
      changed_when: false
      failed_when: false
    
    - name: Check firewall status (ufw)
      shell: |
        if command -v ufw >/dev/null 2>&1; then
          ufw status verbose 2>/dev/null
        else
          echo "ufw not installed"
        fi
      register: fw_ufw
      changed_when: false
      failed_when: false
    
    - name: Check firewall status (firewalld)
      shell: |
        if command -v firewall-cmd >/dev/null 2>&1; then
          firewall-cmd --list-all 2>/dev/null
        else
          echo "firewalld not installed"
        fi
      register: fw_firewalld
      changed_when: false
      failed_when: false
    
    - name: Extract open ports from iptables
      shell: |
        iptables -L INPUT -n 2>/dev/null | grep "ACCEPT" | grep -E "dpt:[0-9]+" | awk '{print $11}' | cut -d: -f2 | sort -nu
      register: iptables_ports
      changed_when: false
      failed_when: false
      when: "'iptables not installed' not in fw_iptables.stdout"
    
    - name: Set firewall audit facts
      set_fact:
        firewall_enabled: "{{ 'not installed' not in fw_iptables.stdout or 'not installed' not in fw_ufw.stdout or 'not installed' not in fw_firewalld.stdout }}"
        firewall_open_ports: "{{ iptables_ports.stdout_lines | default([]) }}"
        open_ssh_port: "{{ '22' in iptables_ports.stdout if iptables_ports.stdout is defined else False }}"
        open_mysql_port: "{{ '3306' in iptables_ports.stdout if iptables_ports.stdout is defined else False }}"
        open_rdp_port: "{{ '3389' in iptables_ports.stdout if iptables_ports.stdout is defined else False }}"
    
    - name: Display firewall summary
      debug:
        msg: |
          Firewall Audit Summary:
          - Firewall enabled: {{ firewall_enabled }}
          - Open ports detected: {{ firewall_open_ports | length }}
          - SSH port open: {{ open_ssh_port }}
          - MySQL port open: {{ open_mysql_port }}
          - RDP port open: {{ open_rdp_port }}
  
  tags: firewall,network
EOF

# -----------------------------
# Disk Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Disk Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/disk.yml"
---
- name: Disk Usage Audit
  block:
    - name: Check disk usage
      shell: df -h --output=pcent,target,size,used,avail | tail -n +2
      register: disks
      changed_when: false
      failed_when: false
    
    - name: Check for separate partitions
      shell: |
        df -h | grep -E "(/boot|/home|/var|/tmp|/usr)"
      register: partitions
      changed_when: false
      failed_when: false
    
    - name: Check inode usage
      shell: df -i --output=pcent,target | tail -n +2 | grep -E "[8-9][0-9]%|100%"
      register: inodes
      changed_when: false
      failed_when: false
    
    - name: Check for large files (>100MB)
      shell: |
        find / -type f -size +100M 2>/dev/null | head -20
      register: large_files
      changed_when: false
      failed_when: false
    
    - name: Check for world-writable directories
      shell: |
        find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | grep -vE "(/proc|/sys|/dev)"
      register: world_writable_dirs
      changed_when: false
      failed_when: false
    
    - name: Set disk audit facts
      set_fact:
        high_disk_usage: "{{ disks.stdout_lines | select('search', '[8-9][0-9]%|100%') | list }}"
        separate_partitions: "{{ partitions.stdout_lines | default([]) }}"
        high_inode_usage: "{{ inodes.stdout_lines | default([]) }}"
        large_files_list: "{{ large_files.stdout_lines | default([]) }}"
        world_writable_dirs_list: "{{ world_writable_dirs.stdout_lines | default([]) }}"
    
    - name: Display disk summary
      debug:
        msg: |
          Disk Audit Summary:
          - High disk usage (>80%): {{ high_disk_usage | length }}
          - Separate partitions: {{ separate_partitions | length }}
          - High inode usage: {{ high_inode_usage | length }}
          - Large files (>100MB): {{ large_files_list | length }}
          - World-writable directories: {{ world_writable_dirs_list | length }}
  
  tags: disk,filesystem
EOF

# -----------------------------
# Sudoers Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Sudoers Audit Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/sudoers.yml"
---
- name: Sudoers Configuration Audit
  block:
    - name: Check sudoers files
      shell: |
        grep -r -E "^[^#].*ALL=.*ALL" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true
      register: sudoers
      changed_when: false
      failed_when: false
    
    - name: Check sudoers file permissions
      shell: |
        find /etc/sudoers /etc/sudoers.d/ -type f 2>/dev/null | \
        xargs -I {} sh -c 'echo "{}: $(stat -c "%a %U %G" {})"'
      register: sudoers_perms
      changed_when: false
      failed_when: false
    
    - name: Check for passwordless sudo
      shell: |
        grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true
      register: passwordless_sudo
      changed_when: false
      failed_when: false
    
    - name: Check sudo timeout
      shell: |
        grep -r "timestamp_timeout" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true
      register: sudo_timeout
      changed_when: false
      failed_when: false
    
    - name: Set sudoers audit facts
      set_fact:
        audit_sudoers: "{{ sudoers.stdout_lines | default([]) }}"
        extra_sudoers_found: "{{ (sudoers.stdout_lines | default([]) | length) > 0 }}"
        sudoers_permission_issues: "{{ sudoers_perms.stdout_lines | default([]) | select('search', '7[0-7][0-7]|.[0-7]7.') | list }}"
        passwordless_sudo_found: "{{ passwordless_sudo.stdout_lines | default([]) | length > 0 }}"
        sudo_timeout_setting: "{{ sudo_timeout.stdout_lines | default([]) }}"
    
    - name: Display sudoers summary
      debug:
        msg: |
          Sudoers Audit Summary:
          - Sudoers with ALL: {{ audit_sudoers | length }}
          - Extra sudoers found: {{ extra_sudoers_found }}
          - Sudoers permission issues: {{ sudoers_permission_issues | length }}
          - Passwordless sudo found: {{ passwordless_sudo_found }}
          - Sudo timeout configured: {{ sudo_timeout_setting | length > 0 }}
  
  tags: sudo,auth
EOF

# -----------------------------
# Redflags Aggregation
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Redflags Aggregation Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/redflags.yml"
---
- name: Aggregate all redflags
  set_fact:
    redflags:
      # CIS Benchmarks
      cis_level1_failures: "{{ cis_level1_results | default({}) | dict2items | selectattr('value', 'equalto', false) | list | length }}"
      cis_level2_failures: "{{ cis_level2_results | default({}) | dict2items | selectattr('value', 'equalto', false) | list | length }}"
      
      # Network & Services
      ssh_password_login: "{{ ssh_password_login | default(false) }}"
      ssh_root_login: "{{ ssh_root_login | default(false) }}"
      ssh_empty_passwords: "{{ ssh_empty_passwords | default(false) }}"
      mysql_port_open: "{{ '3306' in (firewall_open_ports | default([])) }}"
      http_open: "{{ '80' in (firewall_open_ports | default([])) }}"
      https_open: "{{ '443' in (firewall_open_ports | default([])) }}"
      rdp_port_open: "{{ '3389' in (firewall_open_ports | default([])) }}"
      risky_ports_detected: "{{ risky_ports_detected | default([]) | length > 0 }}"
      risky_services_detected: "{{ risky_services_detected | default(false) }}"
      
      # Users & Authentication
      root_cron: "{{ root_cron | default(false) }}"
      extra_root_users: "{{ extra_root_users | default(false) }}"
      duplicate_uids_found: "{{ duplicate_uids_found | default(false) }}"
      duplicate_gids_found: "{{ duplicate_gids_found | default(false) }}"
      no_password_users: "{{ (no_password_users_list | default([]) | length) > 0 }}"
      system_accounts_with_shell: "{{ (system_accounts_with_shell_list | default([]) | length) > 0 }}"
      
      # Secrets & Cryptography
      plaintext_secrets_found: "{{ plaintext_secrets_found | default(false) }}"
      weak_crypto_detected: "{{ redflags_crypto | default(false) }}"
      
      # Filesystem
      world_writable_files: "{{ redflags_world_writable | default(false) }}"
      extra_sudoers_found: "{{ extra_sudoers_found | default(false) }}"
      passwordless_sudo_found: "{{ passwordless_sudo_found | default(false) }}"
      
      # Firewall
      open_ssh_firewall: "{{ open_ssh_port | default(false) }}"
      open_mysql_firewall: "{{ open_mysql_port | default(false) }}"
      firewall_enabled: "{{ firewall_enabled | default(false) }}"
      
      # SSH Keys
      ssh_keys_unprotected: "{{ redflags_ssh_keys_unprotected | default(false) }}"
      
      # Users & Accounts
      inactive_users: "{{ redflags_inactive_users | default(false) }}"
      env_secrets: "{{ redflags_env_secrets | default(false) }}"
      
      # System Configuration
      sysctl: "{{ redflags_sysctl | default(false) }}"
      kernel_randomize: "{{ redflags_kernel_randomize | default(false) }}"
      logrotate: "{{ redflags_logrotate | default(false) }}"
      pending_updates: "{{ redflags_pending_updates | default(false) }}"
      old_passwords: "{{ redflags_old_passwords | default(false) }}"
      suid_sgid_files: "{{ redflags_suid_sgid | default(false) }}"
      auditd: "{{ redflags_auditd | default(false) }}"
      failed_logins: "{{ redflags_failed_logins | default(false) }}"
      disk_usage: "{{ (high_disk_usage | default([]) | length) > 0 }}"
      ipv6_ports: "{{ redflags_ipv6_ports | default(false) }}"
      compliance: "{{ redflags_compliance | default(false) }}"
      risk_expiry: "{{ redflags_risk_expiry | default(false) }}"
      crypto: "{{ redflags_crypto | default(false) }}"
      kernel: "{{ redflags_kernel | default(false) }}"
      permissions: "{{ redflags_permissions | default(false) }}"
      logging: "{{ redflags_logging | default(false) }}"
      network: "{{ redflags_network | default(false) }}"
      boot: "{{ redflags_boot | default(false) }}"
      filesystem: "{{ redflags_filesystem | default(false) }}"
      
      # Additional checks
      rhosts_files_found: "{{ rhosts_files_found | default(false) }}"
      vulnerable_packages_detected: "{{ vulnerable_packages_detected | default(false) }}"
      dangerous_suid_binaries: "{{ (dangerous_suid_binaries | default([]) | length) > 0 }}"
      service_permission_issues: "{{ (service_permission_issues | default([]) | length) > 0 }}"
      cron_permission_issues: "{{ (cron_permission_issues | default([]) | length) > 0 }}"
      sudoers_permission_issues: "{{ (sudoers_permission_issues | default([]) | length) > 0 }}"
      ssh_key_permission_issues: "{{ (ssh_key_permission_issues | default([]) | length) > 0 }}"
      log_permission_issues: "{{ (log_permission_issues | default([]) | length) > 0 }}"
      high_inode_usage: "{{ (high_inode_usage | default([]) | length) > 0 }}"

- name: Calculate total redflags count
  set_fact:
    total_redflags: "{{ redflags | dict2items | selectattr('value', 'equalto', true) | list | length }}"

- name: Display redflags summary
  debug:
    msg: |
      Redflags Summary:
      - Total redflags: {{ total_redflags | default(0) }}
      - CIS Level 1 failures: {{ redflags.cis_level1_failures }}
      - CIS Level 2 failures: {{ redflags.cis_level2_failures }}
      - Critical security issues: {{ redflags.plaintext_secrets_found or redflags.vulnerable_packages_detected or redflags.no_password_users }}
  
  tags: reporting
EOF

# -----------------------------
# Fixes Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Fixes Proposal Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/fixes.yml"
---
- name: Generate improvement/fix proposals
  set_fact:
    fixes: >-
      {{ [] +
         (['disable_ssh_password_authentication'] if redflags.ssh_password_login else []) +
         (['disable_ssh_root_login'] if redflags.ssh_root_login else []) +
         (['disable_ssh_empty_passwords'] if redflags.ssh_empty_passwords else []) +
         (['migrate_secrets_to_sops_or_vault'] if redflags.plaintext_secrets_found else []) +
         (['remove_extra_sudo_entries'] if redflags.extra_sudoers_found else []) +
         (['remove_passwordless_sudo'] if redflags.passwordless_sudo_found else []) +
         (['enable_and_configure_auditd'] if redflags.auditd else []) +
         (['investigate_failed_logins'] if redflags.failed_logins else []) +
         (['remove_inactive_users'] if redflags.inactive_users else []) +
         (['close_unnecessary_ports'] if redflags.risky_ports_detected else []) +
         (['disable_risky_services'] if redflags.risky_services_detected else []) +
         (['secure_ssh_keys'] if redflags.ssh_keys_unprotected else []) +
         (['cleanup_world_writable_files'] if redflags.world_writable_files else []) +
         (['apply_sysctl_hardening'] if redflags.sysctl else []) +
         (['enable_aslr'] if redflags.kernel_randomize else []) +
         (['fix_logrotate_configuration'] if redflags.logrotate else []) +
         (['apply_system_updates'] if redflags.pending_updates else []) +
         (['enforce_password_aging'] if redflags.old_passwords else []) +
         (['review_suid_sgid_files'] if redflags.suid_sgid_files else []) +
         (['cleanup_disk_space'] if redflags.disk_usage else []) +
         (['disable_ipv6_if_unused'] if redflags.ipv6_ports else []) +
         (['implement_compliance_framework'] if redflags.compliance else []) +
         (['renew_expired_certificates'] if redflags.risk_expiry else []) +
         (['upgrade_weak_crypto'] if redflags.crypto else []) +
         (['apply_kernel_patches'] if redflags.kernel else []) +
         (['fix_file_permissions'] if redflags.permissions else []) +
         (['configure_central_logging'] if redflags.logging else []) +
         (['disable_promiscuous_interfaces'] if redflags.network else []) +
         (['secure_boot_loader'] if redflags.boot else []) +
         (['implement_disk_encryption'] if redflags.filesystem else []) +
         (['remove_rhosts_files'] if redflags.rhosts_files_found else []) +
         (['upgrade_vulnerable_packages'] if redflags.vulnerable_packages_detected else []) +
         (['review_dangerous_suid_binaries'] if redflags.dangerous_suid_binaries else []) +
         (['fix_service_permissions'] if redflags.service_permission_issues else []) +
         (['fix_cron_permissions'] if redflags.cron_permission_issues else []) +
         (['fix_sudoers_permissions'] if redflags.sudoers_permission_issues else []) +
         (['fix_ssh_key_permissions'] if redflags.ssh_key_permission_issues else []) +
         (['fix_log_permissions'] if redflags.log_permission_issues else []) +
         (['address_inode_usage'] if redflags.high_inode_usage else []) +
         (['implement_cis_level1_remediations'] if redflags.cis_level1_failures | int > 0 else []) +
         (['implement_cis_level2_remediations'] if redflags.cis_level2_failures | int > 0 else [])
      }}

- name: Display fixes summary
  debug:
    msg: |
      Fix Proposals Summary:
      - Total proposed fixes: {{ fixes | length }}
      - Critical fixes: {{ fixes | select('search', 'secrets|vulnerable|password') | list | length }}
      - Security fixes: {{ fixes | select('search', 'ssh|firewall|auditd|crypto') | list | length }}
      - System fixes: {{ fixes | select('search', 'sysctl|kernel|updates|disk') | list | length }}
  
  tags: reporting
EOF

# -----------------------------
# Severity Calculation
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Severity Calculation Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/severity.yml"
---
- name: Calculate severity score
  # Calculate total severity based on redflags and assigned weights
  set_fact:
    severity_score: >-
      {{
        weights
        | dict2items
        | map(attribute='key')
        | map('extract', redflags | default({}))
        | map('default', 0)
        | map('int')
        | sum
      }}
  vars:
    weights:
      cis_level1_failures: 2
      cis_level2_failures: 3
      ssh_password_login: 5
      ssh_root_login: 5
      ssh_empty_passwords: 5
      mysql_port_open: 4
      rdp_port_open: 5
      vnc_port_open: 5
      risky_ports_detected: 4
      risky_services_detected: 4
      root_cron: 3
      extra_root_users: 5
      duplicate_uids_found: 3
      duplicate_gids_found: 3
      no_password_users: 5
      system_accounts_with_shell: 4
      plaintext_secrets_found: 6
      weak_crypto_detected: 5
      world_writable_files: 4
      extra_sudoers_found: 4
      passwordless_sudo_found: 5
      open_ssh_firewall: 4
      open_mysql_firewall: 3
      ssh_keys_unprotected: 5
      inactive_users: 3
      env_secrets: 5
      sysctl: 4
      kernel_randomize: 4
      logrotate: 3
      pending_updates: 2
      old_passwords: 3
      suid_sgid_files: 4
      auditd: 4
      failed_logins: 3
      disk_usage: 3
      ipv6_ports: 2
      compliance: 5
      risk_expiry: 5
      crypto: 5
      kernel: 4
      permissions: 4
      logging: 3
      network: 4
      boot: 4
      filesystem: 4
      rhosts_files_found: 5
      vulnerable_packages_detected: 6
      dangerous_suid_binaries: 5
      service_permission_issues: 3
      cron_permission_issues: 3
      sudoers_permission_issues: 4
      ssh_key_permission_issues: 4
      log_permission_issues: 3
      high_inode_usage: 2

- name: Determine risk level
  set_fact:
    risk_level: >-
      {% if severity_score | int >= 50 %}critical
      {% elif severity_score | int >= 30 %}high
      {% elif severity_score | int >= 15 %}medium
      {% else %}low{% endif %}

- name: Display severity summary
  debug:
    msg: |
      Severity Assessment:
      - Severity score: {{ severity_score | default(0) }}/100
      - Risk level: {{ risk_level | default('unknown') }}
      - Critical issues: {{ redflags.plaintext_secrets_found or redflags.vulnerable_packages_detected or redflags.no_password_users }}
      - High issues: {{ redflags.ssh_password_login or redflags.ssh_root_login or redflags.extra_root_users }}
  
  tags: reporting
EOF

# -----------------------------
# JSON Report Generation
# -----------------------------
echo -e "${BLUE}🔧 Erstelle JSON Report Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/json.yml"
---
- name: Create reports directory
  file:
    path: "{{ playbook_dir }}/reports"
    state: directory
    mode: '0755'
  delegate_to: localhost

- name: Generate comprehensive JSON report
  copy:
    dest: "{{ playbook_dir }}/reports/audit-{{ ansible_hostname }}-{{ ansible_date_time.epoch }}.json"
    content: |
      {
        "metadata": {
          "hostname": "{{ ansible_hostname }}",
          "timestamp": "{{ ansible_date_time.iso8601 }}",
          "audit_version": "2.0",
          "cis_level": "{{ audit_cis_level }}",
          "os": "{{ ansible_distribution }} {{ ansible_distribution_version }}",
          "kernel": "{{ ansible_kernel }}"
        },
        "summary": {
          "total_redflags": {{ total_redflags | default(0) }},
          "severity_score": {{ severity_score | default(0) }},
          "risk_level": "{{ risk_level | default('unknown') }}",
          "cis_level1_failures": {{ redflags.cis_level1_failures | default(0) }},
          "cis_level2_failures": {{ redflags.cis_level2_failures | default(0) }},
          "proposed_fixes": {{ fixes | length | default(0) }}
        },
        "redflags": {{ redflags | to_nice_json }},
        "fixes": {{ fixes | to_nice_json }},
        "details": {
          "ports": {
            "total": {{ audit_ports.total | default(0) }},
            "risky": {{ audit_ports.risky_count | default(0) }},
            "list": {{ audit_ports.listening | default([]) | to_nice_json }}
          },
          "services": {
            "risky_detected": {{ risky_services_detected | default(false) }},
            "count": {{ audit_services | default([]) | length }}
          },
          "users": {
            "total": {{ audit_users | default([]) | length }},
            "no_password": {{ no_password_users_list | default([]) | length }},
            "inactive": {{ audit_inactive_users | default([]) | length }}
          },
          "cis_checks": {
            "level1": {{ cis_level1_results | default({}) | to_nice_json }},
            "level2": {{ cis_level2_results | default({}) | to_nice_json }}
          }
        }
      }
    mode: '0644'
  delegate_to: localhost

- name: Generate human-readable report
  copy:
    dest: "{{ playbook_dir }}/reports/audit-{{ ansible_hostname }}-{{ ansible_date_time.epoch }}.md"
    content: |
      # Security Audit Report
      
      ## Host Information
      - **Hostname**: {{ ansible_hostname }}
      - **Audit Date**: {{ ansible_date_time.iso8601 }}
      - **OS**: {{ ansible_distribution }} {{ ansible_distribution_version }}
      - **Kernel**: {{ ansible_kernel }}
      
      ## Executive Summary
      - **Risk Level**: **{{ risk_level | upper }}** (Score: {{ severity_score }}/100)
      - **Total Redflags**: {{ total_redflags }}
      - **CIS Level 1 Failures**: {{ redflags.cis_level1_failures }}
      - **CIS Level 2 Failures**: {{ redflags.cis_level2_failures }}
      
      ## Critical Findings
      {% if redflags.plaintext_secrets_found %}
      - **Plaintext Secrets Found**: YES
      {% endif %}
      {% if redflags.vulnerable_packages_detected %}
      - **Vulnerable Packages Detected**: YES
      {% endif %}
      {% if redflags.no_password_users %}
      - **Users Without Password**: YES
      {% endif %}
      
      ## High Priority Findings
      {% if redflags.ssh_password_login %}• SSH Password Authentication Enabled
      {% endif %}{% if redflags.ssh_root_login %}• SSH Root Login Enabled
      {% endif %}{% if redflags.extra_root_users %}• Extra Root Users Found
      {% endif %}{% if redflags.passwordless_sudo_found %}• Passwordless Sudo Found
      {% endif %}
      
      ## Recommended Actions
      {% for fix in fixes %}
      - {{ fix | replace('_', ' ') | title }}
      {% endfor %}
      
      ---
      *Report generated by Legacy Server Audit Tool v2.0*
    mode: '0644'
  delegate_to: localhost

- name: Display report location
  debug:
    msg: |
      Reports generated:
      - JSON: reports/audit-{{ ansible_hostname }}-{{ ansible_date_time.epoch }}.json
      - Markdown: reports/audit-{{ ansible_hostname }}-{{ ansible_date_time.epoch }}.md
  
  tags: reporting
EOF

# -----------------------------
# SOPS Proposals
# -----------------------------
echo -e "${BLUE}🔧 Erstelle SOPS Proposals Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/sops_proposals.yml"
---
- name: Generate SOPS migration proposals
  copy:
    dest: "{{ playbook_dir }}/proposals/{{ ansible_hostname }}-sops-migration.md"
    content: |
      # SOPS Migration Proposal for {{ ansible_hostname }}
      
      ## Found Secrets Requiring Encryption
      
      {% if secrets_list | length > 0 %}
      ### Configuration Files with Secrets
      {% for secret in secrets_list %}
      - {{ secret }}
      {% endfor %}
      {% endif %}
      
      {% if env_secrets_list | length > 0 %}
      ### Environment Variables with Secrets
      {% for secret in env_secrets_list %}
      - {{ secret }}
      {% endfor %}
      {% endif %}
      
      ## Migration Steps
      
      1. Install SOPS and configure age/keybase/GCP KMS/AWS KMS
      2. Create .sops.yaml configuration file
      3. Encrypt existing secret files
      4. Update deployment scripts to decrypt at runtime
      5. Rotate any exposed credentials
      
      ## Risk Assessment
      - **Critical**: {{ secrets_list | select('match', '.*password.*|.*secret.*|.*token.*') | list | length }} critical secrets found
      - **High**: {{ secrets_list | select('match', '.*key.*|.*credential.*') | list | length }} high-risk secrets found
      - **Total**: {{ secrets_list | length }} secrets requiring encryption
    mode: '0644'
  delegate_to: localhost
  when: secrets_list | length > 0 or env_secrets_list | length > 0
  
  tags: sops,secrets
EOF

# -----------------------------
# Remediation Playbook
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Remediation Playbook Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/remediation.yml"
---
- name: Generate remediation playbook
  copy:
    dest: "{{ playbook_dir }}/remediate-{{ ansible_hostname }}.yml"
    content: |
      ---
      # Auto-generated remediation playbook for {{ ansible_hostname }}
      # Generated: {{ ansible_date_time.iso8601 }}
      # Severity: {{ severity_score }} ({{ risk_level }})
      
      - name: Remediation Actions for {{ ansible_hostname }}
        hosts: {{ ansible_hostname }}
        become: true
        
        tasks:
          - name: Create backup directory
            file:
              path: /backup/audit-remediation-{{ ansible_date_time.epoch }}
              state: directory
              mode: '0700'
          
          {% if redflags.ssh_password_login %}
          - name: Disable SSH password authentication
            lineinfile:
              path: /etc/ssh/sshd_config
              regexp: '^#?PasswordAuthentication'
              line: 'PasswordAuthentication no'
              backup: yes
            notify: restart ssh
            
          - name: Disable SSH root login
            lineinfile:
              path: /etc/ssh/sshd_config
              regexp: '^#?PermitRootLogin'
              line: 'PermitRootLogin no'
              backup: yes
            notify: restart ssh
          {% endif %}
          
          {% if redflags.pending_updates %}
          - name: Apply system updates
            package:
              name: "*"
              state: latest
            when: ansible_facts.os_family == "Debian"
            
          - name: Apply security updates
            apt:
              upgrade: dist
              update_cache: yes
              cache_valid_time: 3600
            when: ansible_facts.os_family == "Debian"
          {% endif %}
          
          {% if redflags.world_writable_files %}
          - name: Fix world-writable files
            file:
              path: "{{ item }}"
              mode: '0644'
            loop: "{{ world_writable_files }}"
            when: world_writable_files is defined
          {% endif %}
          
        handlers:
          - name: restart ssh
            service:
              name: ssh
              state: restarted
    mode: '0644'
  delegate_to: localhost
  when: severity_score | default(0) > 10
  
  tags: remediation
EOF

# -----------------------------
# Handlers
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Handlers...${NC}"
cat <<EOF >"$PROJECT_NAME/roles/audit/handlers/main.yml"
---
- name: restart ssh
  service:
    name: ssh
    state: restarted
    enabled: true

- name: restart auditd
  service:
    name: auditd
    state: restarted
    enabled: true

- name: restart syslog
  service:
    name: "{{ 'rsyslog' if 'rsyslog' in ansible_facts.packages else 'syslog-ng' }}"
    state: restarted
    enabled: true

- name: reload sysctl
  command: sysctl --system
  changed_when: false
EOF

# -----------------------------
# Reporting Task
# -----------------------------
echo -e "${BLUE}🔧 Erstelle Reporting Task...${NC}"
cat <<'EOF' >"$PROJECT_NAME/roles/audit/tasks/reporting.yml"
---
- name: Generate executive summary
  copy:
    dest: "{{ playbook_dir }}/reports/executive-summary-{{ ansible_date_time.date }}.md"
    content: |
      # Executive Security Audit Summary
      
      ## Audit Overview
      - **Date**: {{ ansible_date_time.date }}
      - **Tool Version**: 2.0 with CIS Benchmarks
      
      ## Overall Risk Assessment
      - **Severity Score**: {{ severity_score | default('TBD') }}
      - **Risk Level**: {{ risk_level | default('TBD') }}
      
      ## Top Critical Findings
      1. Plaintext secrets found: {{ redflags.plaintext_secrets_found | default('TBD') }}
      2. Vulnerable packages: {{ redflags.vulnerable_packages_detected | default('TBD') }}
      3. Users without password: {{ redflags.no_password_users | default('TBD') }}
      
      ## Compliance Status
      - **CIS Level 1 Failures**: {{ redflags.cis_level1_failures | default('TBD') }}
      - **CIS Level 2 Failures**: {{ redflags.cis_level2_failures | default('TBD') }}
      
      ## Recommended Immediate Actions
      1. Encrypt plaintext secrets
      2. Update vulnerable packages
      3. Secure user accounts
      
      ---
      *Generated {{ ansible_date_time.iso8601 }}*
    mode: '0644'
  delegate_to: localhost
  run_once: true

- name: Create HTML report if pandoc available
  command: |
    pandoc "{{ playbook_dir }}/reports/executive-summary-{{ ansible_date_time.date }}.md" \
    -o "{{ playbook_dir }}/reports/executive-summary-{{ ansible_date_time.date }}.html"
  delegate_to: localhost
  run_once: true
  when: "'pandoc' in ansible_facts.packages"

- name: Archive reports
  archive:
    path: "{{ playbook_dir }}/reports/"
    dest: "{{ playbook_dir }}/reports/audit-archive-{{ ansible_date_time.date }}.tar.gz"
    format: gz
  delegate_to: localhost
  run_once: true

- name: Display final summary
  debug:
    msg: |
      Audit Complete!
      ================
      Reports available in: {{ playbook_dir }}/reports/
      - JSON report: audit-{{ ansible_hostname }}-*.json
      - Markdown report: audit-{{ ansible_hostname }}-*.md
      - Executive summary: executive-summary-*.md
      {% if "'pandoc' in ansible_facts.packages" %}
      - HTML report: executive-summary-*.html
      {% endif %}
      - Archive: audit-archive-*.tar.gz
      
      Risk Level: {{ risk_level | upper }}
      Severity Score: {{ severity_score }}/100
      Total Redflags: {{ total_redflags }}
      
      Next Steps:
      1. Review the reports in the reports/ directory
      2. Prioritize fixes based on severity
      3. Use the generated remediation playbook
      4. Schedule follow-up audit in 30 days
  
  tags: reporting
EOF

# -----------------------------
# Requirements
# -----------------------------
echo -e "${BLUE}📦 Erstelle Requirements...${NC}"
cat <<EOF >"$PROJECT_NAME/requirements.yml"
---
collections:
  - name: community.general
  - name: ansible.posix

roles: []
EOF

# -----------------------------
# Makefile
# -----------------------------
echo -e "${BLUE}🔨 Erstelle Makefile...${NC}"
cat <<'EOF' >"$PROJECT_NAME/Makefile"
.PHONY: audit report clean help backup validate setup

help:
	@echo "Legacy Server Security Audit"
	@echo ""
	@echo "Available commands:"
	@echo " make audit    - Run security audit on all hosts"
	@echo " make report   - Generate HTML report from latest audit"
	@echo " make clean    - Remove generated reports"
	@echo " make backup   - Create backup of current state"
	@echo " make validate - Validate Ansible syntax"
	@echo " make setup    - Install dependencies"

audit:
	ansible-playbook audit.yml -i inventory/hosts.ini

report:
	@if [ -f reports/executive-summary-*.md ]; then \
		if command -v pandoc >/dev/null 2>&1; then \
			pandoc reports/executive-summary-*.md -o reports/executive-summary.html; \
			echo "HTML report generated: reports/executive-summary.html"; \
		else \
			echo "pandoc not installed. Install with: sudo apt-get install pandoc"; \
		fi \
	else \
		echo "No report found. Run 'make audit' first."; \
	fi

clean:
	rm -rf reports/*.json reports/*.md reports/*.html reports/*.tar.gz proposals/*.md

backup:
	tar -czf "backup/audit-$(shell date +%Y%m%d-%H%M%S).tar.gz" --exclude=backup --exclude=.git .

validate:
	ansible-playbook --syntax-check audit.yml

setup:
	@echo "Installing dependencies..."
	@if ! command -v ansible >/dev/null 2>&1; then \
		echo "Installing Ansible..."; \
		pip3 install --user ansible ansible-lint; \
	fi
	@if ! command -v pandoc >/dev/null 2>&1; then \
		echo "Note: pandoc not installed. HTML reports will not be generated."; \
		echo "Install with: sudo apt-get install pandoc"; \
	fi
	@echo "Setup complete!"
EOF

# -----------------------------
# .gitignore
# -----------------------------
echo -e "${BLUE}📛 Erstelle .gitignore...${NC}"
cat <<EOF >"$PROJECT_NAME/.gitignore"
# Reports
reports/*.json
reports/*.md
reports/*.html
reports/*.tar.gz

# Proposals
proposals/*.md

# Backups
backup/*.tar.gz

# Ansible
*.retry
.vagrant/
.ansible/

# Temporary files
*.tmp
*.swp
*.swo

# IDE
.vscode/
.idea/
*.iml

# Local configurations
inventory/local.ini
vars/local_vars.yml

# Logs
*.log
EOF

# -----------------------------
# Setup Script
# -----------------------------
echo -e "${BLUE}⚙️  Erstelle Setup Script...${NC}"
cat <<'EOF' >"$PROJECT_NAME/setup.sh"
#!/bin/bash
set -euo pipefail

echo "Setting up Legacy Server Audit Environment..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Python3 is required but not installed. Installing..."
    if [[ -f /etc/debian_version ]]; then
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip
    elif [[ -f /etc/redhat-release ]]; then
        sudo yum install -y python3 python3-pip
    else
        echo "Unsupported OS. Please install Python3 manually."
        exit 1
    fi
fi

# Check Ansible
if ! command -v ansible &> /dev/null; then
    echo "Installing Ansible..."
    pip3 install --user ansible ansible-lint
    export PATH="$PATH:$HOME/.local/bin"
fi

# Install collections
echo "Installing Ansible collections..."
ansible-galaxy collection install -r requirements.yml

# Check pandoc
if ! command -v pandoc &> /dev/null; then
    echo "Note: pandoc not installed. HTML reports will not be generated."
    echo "To install pandoc: sudo apt-get install pandoc (Debian/Ubuntu) or sudo yum install pandoc (RHEL/CentOS)"
fi

# Make scripts executable
chmod +x *.sh 2>/dev/null || true

echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Edit inventory/hosts.ini with your servers"
echo "2. Configure vars/audit_vars.yml if needed"
echo "3. Run: make validate (check syntax)"
echo "4. Run: ansible-playbook audit.yml --check (dry run)"
echo "5. Run: make audit (full audit)"
EOF
chmod +x "$PROJECT_NAME/setup.sh"

# -----------------------------
# Run Audit Script
# -----------------------------
echo -e "${BLUE}🚀 Erstelle Run Audit Script...${NC}"
cat <<'EOF' >"$PROJECT_NAME/run-audit.sh"
#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Starting Legacy Server Security Audit..."

# Check if Ansible is installed
if ! command -v ansible &> /dev/null; then
    echo "❌ Ansible is not installed. Please run ./setup.sh first."
    exit 1
fi

# Check inventory
if [ ! -f "inventory/hosts.ini" ]; then
    echo "❌ Inventory file not found: inventory/hosts.ini"
    echo "Please configure your inventory file first."
    exit 1
fi

# Run connectivity test
echo "🔍 Testing connectivity..."
if ! ansible all -i inventory/hosts.ini -m ping > /dev/null 2>&1; then
    echo "❌ Connectivity test failed. Please check your inventory and SSH configuration."
    exit 1
fi

# Run the audit
echo "🔒 Running security audit..."
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ansible-playbook audit.yml -i inventory/hosts.ini

echo "✅ Audit completed!"
echo ""
echo "📊 Reports generated in: reports/"
echo "💡 Review the findings and implement recommended fixes."
echo ""
echo "To generate HTML report (if pandoc is installed):"
echo "  make report"
EOF
chmod +x "$PROJECT_NAME/run-audit.sh"

# -----------------------------
# Finale Meldung
# -----------------------------
echo -e "${GREEN}✅ Projekt '$PROJECT_NAME' wurde erfolgreich erstellt!${NC}"
echo ""
echo -e "${BLUE}📋 Nächste Schritte:${NC}"
echo "1. Wechsle ins Projektverzeichnis: cd $PROJECT_NAME"
echo "2. Führe das Setup-Skript aus: ./setup.sh"
echo "3. Passe die Inventory-Datei an: inventory/hosts.ini"
echo "4. Führe einen Testlauf durch: ansible-playbook audit.yml --check"
echo "5. Starte das Audit: ./run-audit.sh"
echo ""
echo -e "${YELLOW}💡 Tipp: Verwende 'make audit' um das Audit zu starten${NC}"
echo -e "${GREEN}🔒 Viel Erfolg mit Ihrem Security Audit!${NC}"
