#!/usr/bin/env bash
# Copy reviewed source only. Activation and PAM setup are separate steps.
set -euo pipefail

update=no
if [[ ${1:-} == --update ]]; then update=yes; shift; fi
if [[ ${1:-} == --help ]]; then
  echo 'Usage: ./scripts/install-plugins.sh [--update]'
  echo 'Copies both plugins into $XDG_CONFIG_HOME/omarchy/plugins (default: ~/.config).'
  echo '--update backs up existing copies; does not enable plugins or change PAM.'
  exit 0
fi
[[ $# == 0 ]] || { echo 'Unexpected arguments; use --help.' >&2; exit 1; }
command -v omarchy >/dev/null || { echo 'A compatible Omarchy installation is required.' >&2; exit 1; }
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
config_root=${XDG_CONFIG_HOME:-"$HOME/.config"}
[[ $config_root == /* ]] || { echo 'XDG_CONFIG_HOME must be absolute.' >&2; exit 1; }
plugin_root="$config_root/omarchy/plugins"

# Validate and preflight both before writing either destination.
for id in yubikey.polkit yubikey.lock; do
  omarchy plugin validate "$source_root/plugins/$id"
  if [[ -L $plugin_root/$id ]]; then
    echo "Refusing symlink destination: $plugin_root/$id" >&2
    exit 1
  fi
  if [[ -e $plugin_root/$id && $update != yes ]]; then
    echo "Already exists: $plugin_root/$id. See docs/plugins.md for updates." >&2
    exit 1
  fi
done
backup_root="${XDG_STATE_HOME:-$HOME/.local/state}/omarchy-yubikey/backups/plugins-$(date -u +%Y%m%d-%H%M%S)-$$"
[[ $backup_root == /* ]] || { echo 'XDG_STATE_HOME must be absolute.' >&2; exit 1; }
mkdir -p -- "$plugin_root"
for id in yubikey.polkit yubikey.lock; do
  if [[ -e $plugin_root/$id ]]; then
    mkdir -p -m 0700 -- "$backup_root"
    mv -- "$plugin_root/$id" "$backup_root/$id"
    printf 'Previous copy backed up: %s\n' "$backup_root/$id"
  fi
  cp -R -- "$source_root/plugins/$id" "$plugin_root/$id"
  printf 'Copied %s\n' "$plugin_root/$id"
done
printf '%s\n' 'Nothing enabled. Follow docs/pam-setup.md and docs/plugins.md next.'
