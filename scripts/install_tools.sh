#!/usr/bin/env bash

set -euo pipefail

TOOLS_FILE="${1:-/opt/work/magno/scripts/tools.yaml}"

log() { echo "[+] $*"; }
warn() { echo "[!] $*"; }
fail() { echo "[-] $*" >&2; exit 1; }

require_root_or_sudo() {
  if [[ "$EUID" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
    fail "Execute como root ou instale sudo."
  fi
}

apt_install() {
  local pkg="$1"

  if dpkg -s "$pkg" >/dev/null 2>&1; then
    log "APT already installed: $pkg"
  else
    log "APT installing: $pkg"
    sudo apt-get install -y "$pkg"
  fi
}

ensure_core() {
  require_root_or_sudo

  log "Updating apt repositories"
  sudo apt-get update

  apt_install git
  apt_install curl
  apt_install wget
  apt_install jq
  apt_install python3
  apt_install python3-pip
  apt_install python3-yaml
  apt_install pipx
  apt_install golang-go

  python3 -m pipx ensurepath >/dev/null 2>&1 || true
}

yaml_get() {
  python3 - "$TOOLS_FILE" "$1" <<'PY'
import sys, yaml

file_path = sys.argv[1]
field = sys.argv[2]

with open(file_path, "r", encoding="utf-8") as f:
    data = yaml.safe_load(f)

if field == "scripts_dir":
    print(data.get("scripts_dir", "/opt/work/magno/scripts"))
    sys.exit(0)

for tool in data.get("tools", []):
    print(tool.get(field, ""))
PY
}

tool_count() {
  python3 - "$TOOLS_FILE" <<'PY'
import sys, yaml
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = yaml.safe_load(f)
print(len(data.get("tools", [])))
PY
}

tool_field() {
  local index="$1"
  local field="$2"

  python3 - "$TOOLS_FILE" "$index" "$field" <<'PY'
import sys, yaml

file_path = sys.argv[1]
index = int(sys.argv[2])
field = sys.argv[3]

with open(file_path, "r", encoding="utf-8") as f:
    data = yaml.safe_load(f)

tools = data.get("tools", [])
value = tools[index].get(field, "")

print(value if value is not None else "")
PY
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_go() {
  local name="$1"
  local binary="$2"
  local module="$3"

  if have_cmd "$binary"; then
    log "$name already available: $binary"
    return
  fi

  log "GO installing $name from $module"
  go install "$module"

  local go_bin
  go_bin="$(go env GOPATH)/bin"

  if [[ -x "$go_bin/$binary" ]]; then
    log "$name installed at $go_bin/$binary"
  else
    warn "$name installed, but binary was not found at expected path: $go_bin/$binary"
  fi
}

install_git() {
  local name="$1"
  local repo="$2"
  local path="$3"
  local scripts_dir="$4"

  local dest="$scripts_dir/$path"

  if [[ -d "$dest/.git" ]]; then
    log "$name already cloned: $dest"
    git -C "$dest" pull --ff-only || warn "Could not update $name"
  else
    log "Cloning $name into $dest"
    git clone "$repo" "$dest"
  fi
}

install_pipx() {
  local name="$1"
  local package="$2"
  local binary="$3"

  if [[ -n "$binary" ]] && have_cmd "$binary"; then
    log "$name already available: $binary"
    return
  fi

  log "PIPX installing $name from $package"
  pipx install "$package" || pipx upgrade "$package" || warn "pipx failed for $name"
}

install_apt_tool() {
  local name="$1"
  local package="$2"
  local binary="$3"

  if [[ -n "$binary" ]] && have_cmd "$binary"; then
    log "$name already available: $binary"
    return
  fi

  apt_install "$package"
}

main() {
  [[ -f "$TOOLS_FILE" ]] || fail "tools.yaml not found: $TOOLS_FILE"

  ensure_core

  local scripts_dir
  scripts_dir="$(python3 - "$TOOLS_FILE" <<'PY'
import sys, yaml
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = yaml.safe_load(f)
print(data.get("scripts_dir", "/opt/work/magno/scripts"))
PY
)"

  sudo mkdir -p "$scripts_dir"
  sudo chown -R "$USER":"$USER" "$scripts_dir" || true

  local count
  count="$(tool_count)"

  log "Tools file: $TOOLS_FILE"
  log "Scripts dir: $scripts_dir"
  log "Tools found: $count"

  for ((i=0; i<count; i++)); do
    local name level domain type package binary module repo path purpose

    name="$(tool_field "$i" name)"
    level="$(tool_field "$i" level)"
    domain="$(tool_field "$i" domain)"
    type="$(tool_field "$i" type)"
    package="$(tool_field "$i" package)"
    binary="$(tool_field "$i" binary)"
    module="$(tool_field "$i" module)"
    repo="$(tool_field "$i" repo)"
    path="$(tool_field "$i" path)"
    purpose="$(tool_field "$i" purpose)"

    echo
    log "$level/$domain :: $name"
    log "Purpose: $purpose"

    case "$type" in
      apt)
        install_apt_tool "$name" "$package" "$binary"
        ;;
      go)
        install_go "$name" "$binary" "$module"
        ;;
      git)
        install_git "$name" "$repo" "$path" "$scripts_dir"
        ;;
      pipx)
        install_pipx "$name" "$package" "$binary"
        ;;
      manual)
        warn "$name requires manual installation/licensing. Skipping."
        ;;
      *)
        warn "Unknown install type for $name: $type"
        ;;
    esac
  done

  echo
  log "Magno tool bootstrap finished."
}

main "$@"
