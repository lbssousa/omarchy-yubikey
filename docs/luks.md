# LUKS2 disk unlock at boot

Version 0.1.1 adds **optional enrollment tooling and a manual boot-integration
guide**. The ordinary desktop installer does not change disk encryption or the
boot path. LUKS uses systemd's own FIDO2 implementation, separately from PAM and
the Keyring helper. No disk password is saved by this project.

The enrollment wizard requests **security-key PIN plus touch**. The existing disk
passphrase remains available. A FIDO2 key with the `hmac-secret` extension is
required; compatibility with PAM alone is insufficient. A key must support a
configured client PIN for the intended PIN-plus-touch policy. Configure its PIN
with the manufacturer's tools first; this wizard does not set or reset it.

## 1. Identify the device and prepare recovery

Use an interactive local terminal with working sudo, a known disk passphrase,
recovery media and private offline storage for the header backup. Do not record
the terminal: systemd displays a new recovery key if you request one.

Inspect your own layout locally with `lsblk -f`, `findmnt /` and
`sudo cryptsetup status YOUR_EXISTING_ROOT_MAPPING`. The enrollment device is
the underlying **LUKS2 partition**, not its already-open `/dev/mapper/...` name,
an entire unrelated disk or a filesystem inside LUKS. Record the current mapping
name and UUID locally. Do not post this output in an issue.

Replace the placeholder below with that partition. Nothing is guessed:

```sh
./install.sh --luks --device /dev/your-luks-partition --check
./install.sh --luks --device /dev/your-luks-partition
```

On Arch the prerequisites are `cryptsetup`, `systemd` and `libfido2`.
`--check` reads the selected header and checks prerequisites; it neither enrolls
a key nor writes backups. It does not establish boot compatibility.

## 2. Enroll and verify

After you explicitly type `ENROLL`, the wizard:

1. Tests the existing disk passphrase with external tokens disabled.
2. Saves a header backup in an owner-only directory under
   `/var/lib/omarchy-yubikey/luks-backups/` (0700 directories, 0600 files).
3. Enrolls one key through `systemd-cryptenroll`, requesting client PIN and touch.
4. Tests **only the newly added token** with `cryptsetup open --test-passphrase
   --token-only --token-id ...`. This does not create another mapping of the
   already-mounted root device.
5. Offers additional backup keys, one connected key at a time, and an optional
   recovery key. Write the recovery key down or save it securely offline.
6. Saves a second header backup after enrollment.

The wizard never formats a device, deletes a slot, restores a header or changes
boot configuration. If interrupted, already-added keys remain enrolled. Review
locally before trying again: another run adds credentials rather than replacing
them. Keep both header backups private and copy them to secure offline storage.
A header backup contains key material protected by the passwords/keys valid
when it was made; it can preserve access through an old, subsequently removed
password. Never attach one to GitHub.

## 3. Preserve a bootable fallback before changing initramfs

This part is manual because kernel image locations, bootloader configuration,
snapshot integration and custom hooks differ between installations. It applies
to **mkinitcpio with Limine and an existing LUKS2 root volume**. Other boot paths,
LVM/RAID, detached headers, keyfiles and multiple early-unlock volumes need their
own review. Do not apply a fixed hook list from another computer.

Before editing anything, privately back up `/etc/mkinitcpio.conf`, its drop-ins,
`/etc/crypttab`, any `/etc/crypttab.initramfs`, and the Limine configuration.
Preserve a copy of the currently working UKI outside the output paths that
`limine-mkinitcpio` rebuilds. Add a manual Limine menu entry pointing to that copy
and verify the entry is selectable. Keep the copy's current kernel command line
and password unlock path. Do not assume snapshots alone provide a fallback.
If you cannot identify and preserve the working image, stop here.

## 4. Configure early unlock

Review [the optional hook drop-in](../luks/zzzz-omarchy-yubikey-luks.conf).
It converts the effective hook list rather than replacing hardware decisions:

| Existing hook | systemd initramfs |
| --- | --- |
| `udev` | `systemd` |
| `encrypt` | `sd-encrypt` |
| `keymap`, `consolefont` | `sd-vconsole` |
| `btrfs-overlayfs` | `sd-btrfs-overlayfs` |
| `resume` | handled by systemd using the existing resume parameters |
| `shutdown` | `sd-shutdown` |

Other supported hooks and their order remain intact, including Plymouth and the
current `kms` choice. Unknown hooks stop the build for manual review. Check that
all required install hooks exist on your machine (`mkinitcpio -L`), especially
`sd-btrfs-overlayfs` if snapshot boot is used. Review all drop-ins in the same
version-sorted order mkinitcpio uses; this drop-in must run last. Remove or adapt
earlier custom FIDO2 overrides only after understanding and backing them up.

From the reviewed checkout, install the drop-in **only if that destination does
not already exist**:

```sh
sudo install -m 0644 luks/zzzz-omarchy-yubikey-luks.conf /etc/mkinitcpio.conf.d/zzzz-omarchy-yubikey-luks.conf
```

For current mkinitcpio versions whose `sd-encrypt` hook supports
`x-initrd.attach`, edit `/etc/crypttab` with `sudoedit`. Add or carefully update
the root entry, using your **existing root mapping name** and the UUID reported
by `sudo cryptsetup luksUUID /dev/your-luks-partition`:

```text
YOUR_EXISTING_ROOT_MAPPING UUID=YOUR_LUKS_UUID none luks,fido2-device=auto,token-timeout=10s,x-initrd.attach
```

If `/etc/crypttab.initramfs` already exists, `sd-encrypt` may use it in preference
to `/etc/crypttab`; review and update the existing early-boot configuration
instead of creating a competing entry. Older mkinitcpio versions require that
file. It uses the same four-column format; `x-initrd.attach` is optional there.
Newer mkinitcpio deprecates that separate file in favor of `/etc/crypttab` with
`x-initrd.attach`. Keep the selected file root-owned and mode 0600. Preserve
unrelated entries; never copy someone else's UUID, mapping or keyfile settings.
Do not enable `headless` or otherwise disable interactive password fallback.

The example does not enable discard. If your existing policy allows discards,
review whether to retain that option. Do not silently import it from a sample.

On the original busybox `encrypt` boot path, `cryptdevice=` can remain in the
kernel command line: systemd uses the crypttab entry instead. Preserve
`root=/dev/mapper/...`, root subvolume options and any `resume`/`resume_offset`
parameters. Existing `rd.luks.*` parameters can override or restrict crypttab
processing and must be reviewed before proceeding.

## 5. Build, inspect and test

Run `sudo limine-mkinitcpio` to rebuild the installed kernel images. Do not
reboot into the new image if any build fails. Inspect the **actual images used
by each boot entry**, using `objcopy --dump-section .initrd=...` for a UKI and
`lsinitcpio` for its initrd, in a private local directory. Check for systemd,
the intended crypttab entry, the FIDO2 cryptsetup plugin and libfido2, keyboard
support, Plymouth if used, snapshot overlay support and resume support if used.
The extracted crypttab contains local identifiers: keep it outside this repo.
Recheck that the preserved fallback image and its menu entry still exist after
rebuilding. Do not rely on a successful build alone.

At the first planned reboot, test PIN plus touch. Then test a second boot with
all security keys unplugged: after the ten-second **device-discovery timeout**,
the disk passphrase must work. This timeout does not limit the PIN prompt when
a key is connected. Do not type the disk passphrase into a security-key PIN
prompt; incorrect PINs consume the key's retry budget. Also check a backup key,
the fallback boot entry, and snapshot/resume paths you use. Keep recovery media
and backups until these checks pass. The enrollment wizard never reboots.

## Rollback

Select the preserved old image if the new image does not boot. Restore the
previous crypttab and mkinitcpio configuration from your private backups,
removing only the drop-in/entry you added, then run `sudo limine-mkinitcpio`.
Keep the fallback image until the restored build boots successfully.
Configuration rollback does **not** remove enrolled tokens; they do not prevent
passphrase boot. Do not restore a whole LUKS header or wipe slots as a routine
configuration rollback. Token removal requires separate review of your current
slots and a tested alternative unlock path.

## Validation and upstream documentation

The original local setup used PIN plus touch, two keys, a recovery key,
systemd initramfs, a ten-second discovery timeout and a preserved fallback UKI.
The extracted wizard and hook conversion have isolated software regression
tests; the generalized 0.1.1 procedure has **not** had a fresh end-to-end hardware
enrollment or reboot qualification. Local experience does not qualify other
hardware or boot layouts. The plugins and Rust helper are unchanged in 0.1.1.

Implementation details were checked against the installed mkinitcpio hooks,
the ArchWiki offline snapshot from October 2026, and current primary references:
[systemd-cryptenroll](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html),
[crypttab](https://www.freedesktop.org/software/systemd/man/latest/crypttab.html),
and [mkinitcpio's sd-encrypt hook](https://gitlab.archlinux.org/archlinux/mkinitcpio/mkinitcpio/-/blob/master/install/sd-encrypt).
