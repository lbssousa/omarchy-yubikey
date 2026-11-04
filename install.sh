#!/usr/bin/env bash
# Interactive installer. No unattended changes to authentication policy.
set -euo pipefail

tr() {
  if [[ -f ${source_root:-}/scripts/i18n.py ]] && command -v python3 >/dev/null; then
    python3 "$source_root/scripts/i18n.py" "$@"
  else
    if [[ $1 == --language-code ]]; then printf en; else printf '%s' "$1"; fi
  fi
}

confirm() {
  local reply prompt=$1 default=${2:-yes}
  prompt=$(tr "$prompt")
  if [[ $default == yes ]]; then prompt+=' [Y/n] '; else prompt+=' [y/N] '; fi
  read -r -p "$prompt" reply </dev/tty || return 1
  reply=${reply:-$default}
  [[ $reply == [yY] || $reply == [yY][eE][sS] ]]
}
pause() { local reply; read -r -p "$(tr "$1") $(tr 'Press Enter when ready.') " reply </dev/tty; }
fail() { printf '\n%s: %s\n' "$(tr 'Setup stopped')" "$(tr "$*")" >&2; exit 1; }

# Also works when this script is fetched through a pipe after public release.
installer_source=${BASH_SOURCE[0]:-}
if [[ -n $installer_source && -f $installer_source ]]; then
  source_root=$(cd -- "$(dirname -- "$installer_source")" && pwd)
else
  source_root=''
fi
if [[ -z $source_root || ! -f $source_root/scripts/configure-pam.py ]]; then
  [[ ${1:-} != --check ]] || fail 'Run --check from a complete checkout.'
  command -v git >/dev/null || fail 'Install git first, then run this installer again.'
  bootstrap_dir=$(mktemp -d "${TMPDIR:-/tmp}/omarchy-yubikey-install.XXXXXX")
  trap 'rm -rf -- "$bootstrap_dir"' EXIT
  git clone --depth 1 --branch v0.3.0 https://github.com/marselnenaj/omarchy-yubikey.git "$bootstrap_dir/source"
  bash "$bootstrap_dir/source/install.sh" "$@" </dev/tty
  exit $?
fi

language=$(tr --language-code)
case ${1:-} in
  --help|-h)
    printf '%s\n' "$(tr 'Usage'): ./install.sh [--check | --rollback BACKUP_ID | --luks --device DEVICE [--check] | --sync export/import ...]" \
      "$(tr 'Guided setup for sudo, desktop authentication and optional GNOME Keyring.')" \
      "$(tr '--sync provides opt-in signed enrollment transfer through a separate private Git checkout; see docs/enrollment-sync.md.')" \
      "$(tr '--luks starts separate opt-in LUKS2 enrollment (PIN + touch); boot setup is manual, see docs/luks.md.')" \
      "$(tr '--check reports prerequisites without changing anything.')" \
      "$(tr '--rollback restores a previous system PAM/enrollment backup; see docs/install.md.')"
    exit 0 ;;
  --luks)
    shift
    exec sudo python3 "$source_root/scripts/enroll-luks.py" --language "$language" "$@" ;;
  --sync)
    shift
    if [[ ${1:-} == import ]]; then
      exec sudo python3 "$source_root/scripts/sync-enrollment.py" --language "$language" "$@"
    fi
    exec python3 "$source_root/scripts/sync-enrollment.py" --language "$language" "$@" ;;
  --check)
    printf '%s\n' "$(tr 'Omarchy YubiKey — prerequisite check (no changes)')"
    for program in bash git python3 sudo pacman pamu2fcfg omarchy omarchy-shell cargo cc ssh-keygen; do
      if command -v "$program" >/dev/null; then printf '  ✓ %s\n' "$program"; else printf '  ✗ %s\n' "$program"; fi
    done
    exit 0 ;;
  --rollback)
    [[ $# == 2 && $2 =~ ^[0-9]{8}-[0-9]{6}-[a-f0-9]{8}$ ]] || fail 'Provide the backup ID printed during setup.'
    exec sudo python3 "$source_root/scripts/configure-pam.py" --language "$language" --rollback "/var/lib/omarchy-yubikey/backups/$2" ;;
  '') ;;
  *) fail 'Unknown option. Run ./install.sh --help.' ;;
esac
[[ $# == 0 ]] || fail 'Unexpected arguments. Run ./install.sh --help.'
[[ $EUID != 0 ]] || fail 'Run as your normal desktop user; the installer uses sudo only when needed.'
[[ -r /dev/tty && -w /dev/tty ]] || fail 'An interactive terminal is required.'
command -v pacman >/dev/null || fail 'Guided setup currently supports Arch Linux and Omarchy. See docs/pam-setup.md for manual setup.'
command -v python3 >/dev/null || fail 'Install Python first: sudo pacman -S --needed python'

printf '\n%s\n\n' "$(tr 'Omarchy YubiKey — guided setup')"
printf '%s\n' "$(tr 'Use y or n; press Enter to accept the displayed default.')"
printf '%s\n' "$(tr 'Choose what to install. Existing password authentication stays available.')"
services=()
use_desktop=no
use_keyring=no
if confirm 'Enable security-key authentication for sudo?'; then services+=(sudo); fi
if command -v omarchy >/dev/null && command -v omarchy-shell >/dev/null; then
  if confirm 'Add desktop touch prompts and security-key screen unlock?'; then
    use_desktop=yes
    services+=(polkit-1 omarchy-lock-fido2)
    omarchy plugin validate "$source_root/plugins/yubikey.polkit"
    omarchy plugin validate "$source_root/plugins/yubikey.lock"
  fi
else
  printf '%s\n' "$(tr 'Desktop integration is unavailable: a compatible Omarchy shell is required.')"
fi
if confirm 'Also install the optional GNOME Keyring helper?' no; then use_keyring=yes; fi
if [[ ${#services[@]} == 0 && $use_keyring == no ]]; then printf '%s\n' "$(tr 'Nothing selected; no changes made.')"; exit 0; fi

config_root=${XDG_CONFIG_HOME:-"$HOME/.config"}
state_root=${XDG_STATE_HOME:-"$HOME/.local/state"}
[[ $config_root == /* && $state_root == /* ]] || fail 'XDG config/state paths must be absolute.'
if [[ $use_desktop == yes ]]; then
  # Some supported shell versions still hardcode ~/.config for plugin discovery.
  [[ $config_root == "$HOME/.config" ]] || fail 'This shell integration currently needs the default ~/.config location. See docs/plugins.md.'
  [[ -f /etc/pam.d/omarchy-lock-password ]] || fail 'The shell password-lock PAM service is missing. Restore the stock lock setup first.'
  lock_state=$(omarchy-shell lock isLocked) || fail 'Cannot query the shell lock state.'
  [[ $lock_state == false || $lock_state == no || $lock_state == 0 ]] || fail 'Unlock the desktop before installing or updating authentication plugins.'
fi

if [[ ${#services[@]} != 0 ]]; then
  auth_mode=pin
  enrollment_options=(-N)
  if ! confirm 'Require your security key FIDO2 PIN as well as touch?'; then
    auth_mode=touch
    enrollment_options=()
    printf '%s\n' "$(tr 'Touch-only mode: anyone holding your key may be able to authenticate.')"
  fi
  fallback=explicit
  if ! confirm 'Require an explicit confirmation before password fallback?'; then fallback=automatic; fi
  printf '\n%s\n' "$(tr 'Key policy: %1; password fallback: %2' "$auth_mode" "$fallback")"
  printf '%s\n' \
    "$(tr 'PAM changes are backed up under /var/lib/omarchy-yubikey/backups.')" \
    "$(tr 'Open a second terminal, run sudo -s, and keep that recovery shell open until testing is complete.')"
  confirm 'Continue with key enrollment and the selected PAM changes?' || exit 0
  sudo pacman -S --needed pam-u2f
  enroll_dir=$(mktemp -d "${TMPDIR:-/tmp}/omarchy-yubikey-enrollment.XXXXXX")
  trap 'rm -rf -- "$enroll_dir"' EXIT
  chmod 700 "$enroll_dir"
  enrollment="$enroll_dir/enrollment"
  pam_options=(--auth-mode "$auth_mode" --fallback "$fallback")
  if [[ -r /etc/fido2/fido2 ]] && awk -F: -v user="$(id -un)" '!/^[[:space:]]*(#|$)/ && $1 != user { found=1 } END { exit !found }' /etc/fido2/fido2; then
    printf '%s\n' "$(tr 'Other accounts have enrolled keys. PAM policy is shared by all accounts; keep the existing policy unless all affected users agree to the change.')"
    if confirm 'Allow the selected PAM policy to change for every account?' no; then
      pam_options+=(--allow-shared-policy-change)
    fi
  fi
  if [[ $fallback == explicit && ( " ${services[*]} " == *' sudo '* || " ${services[*]} " == *' polkit-1 '* ) ]]; then
    sudo pacman -S --needed base-devel pam
    bash "$source_root/scripts/build-pam-gate.sh" "$enroll_dir/pam_omarchy_fallback.so"
    pam_options+=(--fallback-module "$enroll_dir/pam_omarchy_fallback.so")
  fi
  umask 077
  pause 'Plug in only the key to enroll; enter its PIN if requested and touch when it blinks. PIN mode needs a PIN already set on the key.'
  pamu2fcfg "${enrollment_options[@]}" -u "$(id -un)" -o pam://omarchy -i pam://omarchy > "$enrollment"
  while confirm 'Enroll a backup key too?' no; do
    pause 'Unplug the previous key and plug in only the backup key.'
    pamu2fcfg "${enrollment_options[@]}" -n -o pam://omarchy -i pam://omarchy >> "$enrollment"
  done
  sudo python3 "$source_root/scripts/configure-pam.py" --language "$language" "${pam_options[@]}" --user "$(id -un)" --enrollment "$enrollment" --services "${services[@]}"
  confirm 'Apply the listed changes? Existing user/key mappings will be preserved.' || exit 0
  sudo python3 "$source_root/scripts/configure-pam.py" --language "$language" "${pam_options[@]}" --apply --user "$(id -un)" --enrollment "$enrollment" --services "${services[@]}"

  if [[ " ${services[*]} " == *' sudo '* ]]; then
    pause 'Test password fallback: unplug all security keys now. In explicit mode, type the literal word password at the fallback choice, then enter your account password at its separate prompt.'
    sudo -k
    sudo true || fail 'Password verification failed. Use the recovery shell to roll back; desktop plugins have not been enabled.'
    pause 'Test the key: plug in an enrolled key and touch it when sudo asks.'
    sudo -k
    sudo true || fail 'Key test did not succeed. See docs/install.md; desktop plugins have not been enabled.'
    printf '%s\n' "$(tr 'sudo tests completed. Close the recovery shell only after desktop testing too.')"
  fi
  rm -rf -- "$enroll_dir"
  trap - EXIT
fi

if [[ $use_desktop == yes || $use_keyring == yes ]]; then
  user_backup="$state_root/omarchy-yubikey/backups/$(date -u +%Y%m%d-%H%M%S)-$$"
  mkdir -p -m 0700 -- "$user_backup"
  chmod 700 "$state_root/omarchy-yubikey" "$state_root/omarchy-yubikey/backups"
  printf '\n%s\n' "$(tr 'User-file backup: %1' "$user_backup")"
fi

if [[ $use_desktop == yes ]]; then
  # Keep a shell-config snapshot before changing which authentication clones run.
  if [[ -f $config_root/omarchy/shell.json ]]; then
    cp -- "$config_root/omarchy/shell.json" "$user_backup/shell.json"
    chmod 600 "$user_backup/shell.json"
  fi
  replacements=$(python3 - "$config_root" <<'PY'
import json
from pathlib import Path
import sys
config = Path(sys.argv[1]) / 'omarchy'
path = config / 'shell.json'
settings = json.loads(path.read_text()) if path.exists() else {}
for entry in settings.get('plugins', []):
    identity = entry.get('id', '') if isinstance(entry, dict) else str(entry)
    # The host supports simple plugin IDs; do not treat metadata as a path.
    if not identity or '/' in identity or '..' in identity:
        continue
    manifest = config / 'plugins' / identity / 'manifest.json'
    if manifest.is_file():
        metadata = json.loads(manifest.read_text()).get('omarchy', {})
        if metadata.get('clonedFrom') in ('omarchy.polkit', 'omarchy.lock'):
            print(identity)
PY
)
  while IFS= read -r identity; do
    [[ -z $identity ]] || omarchy plugin disable "$identity"
  done <<< "$replacements"
  "$source_root/scripts/install-plugins.sh" --update
  omarchy-shell shell rescanPlugins
  omarchy plugin enable yubikey.polkit
  omarchy plugin enable yubikey.lock
  printf '%s\n' "$(tr 'Desktop plugins enabled. Test a benign Polkit action, then a real lock with key and password.')" \
    "$(tr 'Keep your recovery shell open until both unlock methods work. See docs/install.md for rollback.')"
fi

if [[ $use_keyring == yes ]]; then
  printf '%s\n' "$(tr 'The optional Keyring helper is independent of PAM: it still decrypts with touch only, even when PAM requires a PIN.')"
  confirm "$(tr 'Continue with touch-only Keyring enrollment?')" no || { printf '%s\n' "$(tr 'Keyring skipped. Selected PAM/desktop setup is complete.')"; exit 0; }
  sudo pacman -S --needed base-devel rust clang pkgconf libfido2 openssl systemd-libs gnome-keyring
  cargo build --manifest-path "$source_root/Cargo.toml" --target-dir "$source_root/target" --release --locked -p keyring-unlock
  mkdir -p -- "$HOME/.local/bin"
  binary="$HOME/.local/bin/keyring-unlock"
  store=${KEYRING_UNLOCK_STORE:-"$config_root/keyring-unlock/password.json"}
  [[ $store == /* && ! -L $store && ! -L $binary ]] || fail 'Keyring store/binary must use normal absolute paths, without symlinks.'
  if [[ -f $binary ]]; then cp -p -- "$binary" "$user_backup/keyring-unlock"; fi
  if [[ -f $store ]]; then cp -- "$store" "$user_backup/password.json"; chmod 600 "$user_backup/password.json"; fi
  install -m 0755 "$source_root/target/release/keyring-unlock" "$binary"
  printf '%s\n' "$(tr 'Enter the existing default keyring password when asked. No new account password is created.')"
  if ! "$binary" enroll || ! "$binary" check; then
    if [[ -f $user_backup/keyring-unlock ]]; then cp -p -- "$user_backup/keyring-unlock" "$binary"; else rm -f -- "$binary"; fi
    if [[ -f $user_backup/password.json ]]; then cp -- "$user_backup/password.json" "$store"; chmod 600 "$store"; else rm -f -- "$store"; fi
    fail 'Keyring enrollment/check failed; the previous binary and encrypted store were restored.'
  fi
  if confirm 'Try unlocking GNOME Keyring now?'; then "$binary" unlock; fi
  if [[ -z ${KEYRING_UNLOCK_STORE:-} && $config_root == "$HOME/.config" ]] && confirm 'Unlock GNOME Keyring with a touch at each graphical login?'; then
    mkdir -p -- "$config_root/systemd/user"
    if [[ -f $config_root/systemd/user/keyring-unlock.service ]]; then cp -- "$config_root/systemd/user/keyring-unlock.service" "$user_backup/keyring-unlock.service"; fi
    install -m 0644 "$source_root/systemd/keyring-unlock.service" "$config_root/systemd/user/"
    systemctl --user daemon-reload
    systemctl --user enable keyring-unlock.service
  fi
fi
printf '\n%s\n' "$(tr 'Setup complete. Documentation: https://github.com/marselnenaj/omarchy-yubikey#documentation')"
