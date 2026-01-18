<div align="center">

# 🔐 Secure tmux

### Security-Hardened Terminal Multiplexer

[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Platform](https://img.shields.io/badge/Platform-Linux%20|%20macOS%20|%20BSD-lightgrey.svg)]()

*A security-hardened fork of tmux addressing common vulnerabilities in multi-user terminal environments.*

</div>

---

## ✨ Security Features

### 🔑 1. Session Passcode Protection

Protect your sessions with a passcode that other users must enter to attach.

<details>
<summary><strong>Usage Examples</strong></summary>

```bash
# Create session with passcode
tmux new-session -s mysession -p "secretpass"

# Set passcode on existing session
tmux session-passcode -t mysession "secretpass"

# Attach to protected session
tmux attach -t mysession -p "secretpass"

# Check passcode status
tmux session-passcode -t mysession

# Clear passcode
tmux session-passcode -c -t mysession
```

</details>

> **Note:** Session owners and root do not need to enter the passcode.

---

### 🛡️ 2. Socket Directory Hardening

Enhanced protection against symlink attacks and unauthorized access.

| Protection | Description |
|------------|-------------|
| **Secure Locations** | Prefers `$XDG_RUNTIME_DIR` → `/run/user/$UID` → `/tmp` |
| **Symlink Prevention** | Uses `O_NOFOLLOW` to prevent symlink attacks |
| **Ownership Validation** | Validates directory ownership before socket creation |
| **Strict Permissions** | Enforces mode `0700` on socket directories |
| **TOCTOU Safety** | Uses `openat()` for race-condition-free validation |

<details>
<summary><strong>Configuration</strong></summary>

```bash
set -g socket-path-validate on       # Enable path validation (default: on)
set -g socket-strict-permissions on  # Enforce strict permissions (default: on)
```

</details>

---

### 📋 3. Clipboard Security

Protection against clipboard poisoning and data leakage attacks.

| Protection | Description |
|------------|-------------|
| **Escape Sanitization** | Removes dangerous escape sequences from clipboard data |
| **Control Char Filtering** | Filters BEL, BS, ESC, and other control characters |
| **Size Limits** | Prevents memory exhaustion via oversized clipboard data |
| **Audit Logging** | Logs clipboard access for security monitoring |

<details>
<summary><strong>Configuration</strong></summary>

```bash
set -g clipboard-sanitize on         # Enable sanitization (default: on)
set -g clipboard-max-size 1048576    # Max size in bytes (default: 1MB)
```

</details>

---

### 🔒 4. Environment Variable Protection

Prevents SSH agent hijacking and malicious environment variable injection.

| Protection | Description |
|------------|-------------|
| **SSH_AUTH_SOCK Validation** | Validates existence, type, and ownership |
| **KRB5CCNAME Validation** | Validates Kerberos credential cache files |
| **Dangerous Variable Blocking** | Blocks `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, etc. |
| **Custom Deny Lists** | Supports explicit deny lists for additional blocking |

<details>
<summary><strong>Configuration</strong></summary>

```bash
set -g secure-update-environment on
set -s update-environment-deny "LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES"
```

</details>

---

### 🚫 5. Escape Sequence Filtering

Protection against terminal escape sequence injection attacks.

| Protection | Description |
|------------|-------------|
| **Title Sanitization** | Sanitizes window and pane titles |
| **Control Output Filtering** | Filters control mode output |
| **Sequence Removal** | Removes CSI, OSC, and DCS escape sequences |
| **Strict Mode** | Only allows printable ASCII in titles |

<details>
<summary><strong>Configuration</strong></summary>

```bash
set -g title-sanitize 1              # 0=off, 1=on, 2=strict (default: 1)
set -g control-output-sanitize on    # Sanitize control mode output (default: on)
```

</details>

---

### 👥 6. Per-Session Access Control

Fine-grained access control for each session.

| Feature | Description |
|---------|-------------|
| **Owner Tracking** | Each session tracks its owner (UID) |
| **Private Sessions** | Owner-only access mode |
| **Session Locking** | Prevent new attachments |
| **User Permissions** | Per-user read-only or read-write access |
| **Automatic Enforcement** | ACL checked automatically on attach |

---

## ⚡ Quick Setup

Add to your `~/.tmux.conf` for maximum security:

```bash
# Socket Security
set -g socket-path-validate on
set -g socket-strict-permissions on

# Clipboard Security
set -g clipboard-sanitize on
set -g clipboard-max-size 1048576

# Environment Security
set -g secure-update-environment on
set -s update-environment-deny "LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES"

# Escape Sequence Security
set -g title-sanitize 1
set -g control-output-sanitize on
```

---

## 📖 Command Reference

### New Commands

| Command | Description |
|---------|-------------|
| `session-passcode [-c] [-t target] [passcode]` | Set, check, or clear session passcode |

**Alias:** `sessp`

**Options:**
- `-c` — Clear the passcode
- `-t target-session` — Target session

### Modified Commands

| Command | New Option | Description |
|---------|------------|-------------|
| `new-session` | `-p passcode` | Set session passcode on creation |
| `attach-session` | `-p passcode` | Provide passcode to attach |

---

## 📦 About tmux

tmux is a terminal multiplexer: it enables a number of terminals to be created, accessed, and controlled from a single screen. tmux may be detached from a screen and continue running in the background, then later reattached.

**Supported Platforms:** OpenBSD, FreeBSD, NetBSD, Linux, macOS, Solaris

---

## 🔧 Installation

### Dependencies

- **libevent 2.x** — https://github.com/libevent/libevent/releases/latest
- **ncurses** — https://invisible-mirror.net/archives/ncurses/
- **Build tools:** C compiler (gcc/clang), make, pkg-config, yacc/bison

### From Release Tarball

```bash
./configure && make
sudo make install
```

### From Source (requires autoconf, automake, pkg-config)

```bash
git clone https://github.com/tmux/tmux.git
cd tmux
sh autogen.sh
./configure && make
sudo make install
```

> **Tip:** Use `--enable-utempter` to enable utmp(5) updates.

---

## 📚 Documentation

- **Man page:** `nroff -mdoc tmux.1 | less`
- **Example config:** `example_tmux.conf`
- **Wiki:** https://github.com/tmux/tmux/wiki
- **FAQ:** https://github.com/tmux/tmux/wiki/FAQ
- **Bash completion:** https://github.com/scop/bash-completion/blob/main/completions/tmux
- **Debugging:** Run with `-v` or `-vv` for logs

---

## 🤝 Contributing

Bug reports, feature suggestions, and code contributions are welcome!

- **Email:** tmux-users@googlegroups.com
- **GitHub:** Open an issue or pull request
- **Subscribe:** tmux-users+subscribe@googlegroups.com

---

## 📄 License

This file and CHANGES are licensed under the **ISC License**.  
All other files have a license and copyright notice at their start.
