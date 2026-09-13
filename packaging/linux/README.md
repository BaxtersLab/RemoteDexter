# Linux packaging — the optional `/dev/uinput` grant

RemoteDexter injects input through `uinput`, the kernel's virtual input device.
`/dev/uinput` is not writable by ordinary users, so something has to grant it.

The usual answer is `usermod -aG input $USER`. RemoteDexter refuses that answer.
The `input` group also owns `/dev/input/event*` — every physical keyboard and
mouse on the machine. Joining it to move a cursor hands *every process running
as that user* a live keylogger, permanently, whether RemoteDexter is running or
not. That is a much larger grant than the feature needs.

What is installed instead is one udev rule:

```udev
KERNEL=="uinput", SUBSYSTEM=="misc", TAG+="uaccess"
```

`uaccess` is systemd's mechanism for handing a device to whoever is physically
sitting at the machine: logind puts an ACL on the node for the user of the
**active local seat**, and takes it away when that session ends. So the grant

* covers `/dev/uinput` and nothing else — `/dev/input/event*` stays unreadable;
* follows the seat, so a remote SSH user does not inherit it;
* disappears when the user logs out.

## What is installed where

| file | installed to | owner | notes |
|---|---|---|---|
| `70-remotedexter-uinput.rules` | `/usr/share/remotedexter/` | `root:root 0644` | **inert package data.** Not under `/etc/udev/rules.d`. |
| `remotedexter-enable-input` | `/usr/libexec/remotedexter/` | `root:root 0755` | the only privileged operation |
| `debian/postinst` | maintainer script | — | deliberately inert |
| `debian/postrm` | maintainer script | — | removes the optional rule on `purge` only |

Installing the package changes **no** device ACL, group membership, udev rule,
unit, process, socket or key. The rule reaches `/etc/udev/rules.d` only when the
user presses **Enable input** in the host UI.

## Why `pkexec` and not a polkit policy of our own

The UI runs

```sh
pkexec /usr/libexec/remotedexter/remotedexter-enable-input enable
```

`pkexec` with no shipped `.policy` file falls back to
`org.freedesktop.policykit.exec`, which asks for ordinary administrator
authentication every time. A RemoteDexter `.policy` saying `allow_active=yes`
would turn that into a standing, silent grant — the exact thing this design
exists to avoid. There is no RemoteDexter polkit rule, no root daemon, no
socket, no setuid binary and no IPC surface.

## The helper's contract

```
remotedexter-enable-input enable | disable | status
```

Exactly one argument, from that fixed set, checked before any filesystem or
privilege operation. It takes **no** path and **no** rule text — not by
argument, not by environment. Destination, source and temporary-file prefix are
literal constants in the script.

Output is `key=value` lines on stdout. Exit codes: `0` ok, `2` bad arguments,
`3` refused unsafe existing state, `4` operation failed, `5` not root.

It fails closed when `/etc/udev/rules.d/70-remotedexter-uinput.rules` is a
symlink, a directory, a non-regular file, not root-owned, group/world-writable,
or holds content RemoteDexter did not write. It never overwrites such a file and
never deletes one.

`enable` writes to a temporary name in the same directory, flushes it, and
renames it into place. `rename(2)` within a directory is atomic, so an
interruption leaves either no rule or the complete rule. The temporary name does
not end in `.rules`, so udev would not read a half-written one even in the
instant it exists.

## What the grant does NOT let you do, on purpose

`uaccess` covers `/dev/uinput`. It does not cover the `/dev/input/event*` nodes,
including the ones the kernel creates for RemoteDexter's *own* virtual devices.
So with the grant live, the user can create virtual devices and inject events,
and cannot read events back from any node — physical or virtual.

That surprises people, and it is worth stating plainly because it looks like a
gap and is not. A machine where RemoteDexter's user could read event nodes is a
machine where RemoteDexter's user could read the physical keyboard: the two are
the same permission. The compositor is unaffected — GNOME receives input device
fds from logind, not by opening the nodes itself, which is why injection reaches
the desktop normally.

The practical consequence is confined to testing.
`scripts/test-uinput-install.sh` therefore runs the two hardware tests at two
different privilege levels: the device-lifecycle test as the ordinary seat user
with only this grant (check 15), and the exact event readback as root (check 21),
because the verification instrument needs a privilege the product deliberately
does not have.

## Disable has to do more than delete a file

`uaccess` only ever *grants*. Nothing revokes an ACL when the tag stops being
there, so removing the rule leaves the user able to write `/dev/uinput` for the
rest of that login session. Measured in the harness on 2026-08-23: after
`disable`, the device still carried `user:baxter:rw-`.

So `disable` reloads the rules, retriggers `uinput` so the device is re-derived
from the rule set that no longer includes ours, clears the ACL with `setfacl -b`,
and retriggers once more so that any *other* rule still entitled to grant this
device re-applies its own. What is left afterwards is exactly what the current
rules say — and that is what gets reported.

The ordering matters and the first version got it wrong. `udevadm control
--reload-rules` is asynchronous: clearing the ACL first loses the race, because
the retrigger is processed under the old rule set and hands the grant straight
back. `postrm purge` carries the same sequence for the same reason.

When `setfacl` is unavailable, the helper reports `acl_reset=unavailable` and the
console says the rule is removed but access persists until sign-out. It does not
say "disabled". The same honest state covers an account that is a member of
`input`, where no rule RemoteDexter installs or removes can change anything.

## "Installed" is not "working"

`uaccess` applies when logind processes the device event for the active seat.
The helper therefore does not claim success by having written a file: after
reloading and re-triggering `uinput` alone, it becomes the target user and tries
to open the device. `session_refresh_required=yes` means the rule is in place but
this session does not have access yet and the user must log out and back in (or
reboot). The host UI shows that state as itself and does not say "enabled".

## Uninstall and purge

* `apt remove` leaves the rule in place. It is user-chosen state.
* `apt purge` removes it, but only if it is still a regular, non-symlink,
  root-owned file whose bytes match what RemoteDexter installs. A file that has
  been edited or replaced is left alone and reported, and the purge still
  succeeds.

Building the actual `.deb` — control file, install paths, zero-idle-footprint
verification — belongs to Block 13. Block 7 ships the rule, the helper, the two
maintainer scripts that must be correct for the grant to be reversible, and
`scripts/test-uinput-install.sh`, which proves all of it against real udev and
real logind in `BaxtersVMHarness`.

## Supported ground

Proven on Ubuntu 26.04 (systemd 259) in `BaxtersVMHarness`. `uaccess` behaviour
varies between distributions; anything else is undocumented and untested here.
Headless multi-user servers and remote-login sessions with no active local seat
are explicitly out of scope — there is no seat for `uaccess` to grant to.
