# Running your own RemoteDexter relay

RemoteDexter works on a local network with no relay at all. A relay is only
needed to reach a host that cannot accept an inbound connection — behind CGNAT,
a corporate firewall, or a VPN you do not control.

**You do not need anyone else's relay.** The server is in this repository, it is
one binary with no database and no state on disk, and this document is how to
run it.

---

## What the relay can and cannot see

This is the whole design, and it is worth understanding before you run one.

**The relay splices ciphertext and nothing else.** The phone and the host run a
Noise XX handshake end to end *through* the relay, with the host's static key
pinned in the pairing invite. The relay copies bytes between two sockets and
never inspects them.

So a relay operator — including you, and including anyone who compromises your
server — **cannot**:

* read a session, or any part of one;
* modify a session without the Noise transport detecting it;
* impersonate a host, because the handshake would fail against the pinned key;
* learn a pairing token, which travels encrypted *inside* the session.

What a relay operator **can** see: that a particular host is registered, that
someone connected to it, how many bytes went each way, and for how long.
Metadata, not content.

This is structural, not a promise. `crates/relay` has **no dependency that could
decrypt** — no `snow`, no session types. `snow` appears only as a
*dev-dependency*, for one test that runs a genuine Noise session through the
relay and asserts the plaintext appears nowhere in the bytes the relay handled.
If a future change moves it to `[dependencies]`, the relay has gained the
ability to decrypt and this section is no longer true.

---

## Build

```bash
cargo build --release -p relay --bin relayd
```

The binary lands at `target/release/relayd`. It needs no other files.

---

## Run

`relayd` has **no defaults**. It refuses to start without an address, an
authentication method, and credentials — because a relay that started with
defaults would be one accepting any host that asked, on an address nobody chose.

### Shared secret (simplest)

```bash
RD_RELAY_BIND=203.0.113.9:9443 \
RD_RELAY_AUTH=bearer \
RD_RELAY_TOKENS="$(cat /etc/remotedexter/relay-token)" \
  ./target/release/relayd
```

`RD_RELAY_TOKENS` is a comma-separated list, so several hosts can share one
relay with their own credentials. The relay stores only a SHA-256 of each, so
relay state that leaks yields no working credential — but the secret itself does
cross the wire on every registration, and a replayed registration frame is a
registration.

### Signed identity (recommended for a relay on a public address)

```bash
RD_RELAY_BIND=203.0.113.9:9443 \
RD_RELAY_AUTH=signing \
RD_RELAY_HOSTS="Md6+VdN8cidosTcTHKpghwgLLgtguUvXhdFFdc+kmLw=" \
  ./target/release/relayd
```

`RD_RELAY_HOSTS` is a comma-separated list of base64 Ed25519 **public** keys —
the host identity keys your hosts already have. The relay issues a random
challenge and the host signs it, so **nothing replayable crosses the wire**.

Which to choose: `bearer` for a relay you run for yourself; `signing` for one
reachable from the internet, or one serving hosts you do not personally control.

### Which port, and what to expose

One port carries everything — host control connections, clients, and host data
connections, told apart by their first frame. That is one firewall rule.

Nothing else needs to be open. The relay makes no outbound connections of its
own and writes nothing to disk.

---

## Verify it

```bash
./scripts/relayd-smoke.sh
```

This builds `relayd`, starts it on a free loopback port, and drives it from
outside the process — a full session, a replayed ticket refused, and the same
session id serving a second client after the first leaves. It is written in
Python against the wire format *as documented*, so it catches a mismatch that
the Rust tests cannot: they speak the format through the same code that produces
it.

---

## Point a host at it

The ordinary way is the console, which remembers the relay. Everything below
about environment variables still works, and still wins for the run it is set in.

### From the console (remembered)

In the host window, under **Relay**:

1. Type the relay's `address:port` and press **Remember this relay**. It is
   written to `settings.json` beside the host's identity — see
   [Where the host keeps this](#where-the-host-keeps-this).
2. Press **Connect via relay** to connect now, or tick **Connect through the
   relay whenever RemoteDexter starts** to have every launch do it.

A **remembered relay needs no environment variable at all**, which is the point:
a host started from the application grid can use one. It is always `signing` —
the file can express no other method, because the alternative needs a token, and
a token in a settings file is a credential at rest that nobody chose to store.

**"Connect whenever RemoteDexter starts" is off until you turn it on**, and the
first time you do, the console says plainly what it means: while RemoteDexter
runs it holds an outbound connection to the relay, so the relay's operator can
see that this host is online, for how long, and how many bytes crossed — never
what they are. Nothing is captured, injected or offered by it: a phone still has
to be paired, and each session still needs consent. One click turns it off
again, and that sticks too.

An address must be an `address:port`, **never a name**. A name would be resolved
at every start — it can hang, it can be answered by whatever the current
network's resolver says, and this host has pinned the key of one particular
relay.

If the relay cannot be reached, the host **keeps trying** — after 1 second, then
2, 4, 8 … up to a minute between attempts — and the console says which attempt
it is on and when the next one is. If the relay ANSWERS and refuses the host, it
stops and shows the relay's reason: a credential the relay has rejected will be
rejected again, and retrying would bury the reason under the next attempt.

### Where the host keeps this

`settings.json`, in the host's own data directory beside its identity and its
paired-device list:

| | |
|---|---|
| Linux | `${XDG_DATA_HOME:-~/.local/share}/remotedexter/settings.json` |
| Windows | `%APPDATA%\remotedexter\settings.json` |

Owner-only (`0600`, in a `0700` directory), written atomically, and **never
holding a secret**. A file the host cannot parse leaves it on deny-by-default
defaults with a line saying so, and **the file is left exactly as it is** so it
can be fixed by hand. Fields a newer build wrote survive an older one reading
and rewriting it.

### From the environment (this run only)

On the host machine, before starting the console. **The method is named on
both sides and is never inferred** — a host that decided it from whether a token
happened to be set could silently downgrade itself to a weaker credential.

Against a `bearer` relay:

```bash
RD_RELAY=203.0.113.9:9443 \
RD_RELAY_AUTH=bearer \
RD_RELAY_TOKEN="$(cat ~/.config/remotedexter/relay-token)" \
  ./run.sh
```

Against a `signing` relay — **no extra secret to distribute.** The host proves
itself with the invite-signing identity it already has, and the relay holds only
the public half:

```bash
RD_RELAY=203.0.113.9:9443 RD_RELAY_AUTH=signing ./run.sh
```

To enrol that host, take the line the console prints at startup —
`Invite-signing identity pubkey: …` — and add it to the relay's
`RD_RELAY_HOSTS`. It is a public key; it is safe to copy and to store.

If `RD_RELAY` is set but the rest is wrong, the host says so on stderr **and in
the console's Relay section**, and offers no relay button. A misconfigured relay
must not look identical to one that was never configured: "you have not set this
up" and "what you set up is wrong" are different problems with different fixes.

`RD_RELAY` also **overrides a remembered relay for that run**, and the console
says which address is in force and where it came from. The file is never written
from the environment, so a development run against a throwaway relay cannot
quietly become the remembered one.

The console then offers **Connect via relay**. A host connected this way **binds
nothing** — it holds one outbound control connection and opens a second
connection per client, on demand. The console says so: *"Reachable through relay
… — nothing is listening here."*

Its pairing code is a **v5 invite**, naming the relay and the session id rather
than an address. It is signed exactly as a direct invite is, and it carries the
same pinned host key.

---

## Banning scanners with fail2ban

A relay on a public address is found by scanners within hours. They cannot get
in, but they fill the log and occupy connection slots. `crates/relay/deploy/fail2ban/`
holds a filter and a jail that ban them from the relay's port only.

```bash
sudo install -m 0644 crates/relay/deploy/fail2ban/filter.d/remotedexter-relay.conf /etc/fail2ban/filter.d/
sudo install -m 0644 crates/relay/deploy/fail2ban/jail.d/remotedexter-relay.local  /etc/fail2ban/jail.d/
fail2ban-regex crates/relay/deploy/fail2ban/sample.log /etc/fail2ban/filter.d/remotedexter-relay.conf
sudo fail2ban-client reload
```

`fail2ban-regex` on the sample must report **6 matched, 13 missed**. The jail
expects `relayd` to run as the systemd unit `remotedexter-relay.service` and
the relay on port 9443; change `journalmatch` and `port` if yours differ.

### What it bans, and what it never bans

It bans on exactly two lines:

| line | why it is safe to ban on |
|---|---|
| `[relayd] <peer>: frame too large` | a length prefix past the control-frame cap |
| `[relayd] <peer>: malformed frame` | a body that is not a control frame |

Every RemoteDexter host and phone speaks the relay's framing, so neither line
can come from a real user, however bad their network. Everything else `relayd`
says is deliberately **not** a trigger:

| line | why it must not ban |
|---|---|
| `not authorised` | a host with a wrong or old credential — misconfigured, not hostile |
| `no such session` | a phone with a stale invite |
| `unsupported protocol version` | an old or newer client |
| `unexpected frame`, `empty frame` | protocol mistakes that are not scanner signatures |
| `relay at capacity` | the relay is full; the peer did nothing wrong |
| `connection closed` | an ordinary disconnect |
| `no frame within 10 s` | a silent socket; a phone on a bad network looks the same |
| `session ended: one side took nothing for 30 s` | a phone that lost its network mid-session |
| `refused …: 256 connections already unauthenticated` | the relay's own load shedding |

### Escalation

Three trigger lines from one address within 10 minutes bans that address from
TCP 9443 for **1 hour**. Its next ban is **24 hours**, and every one after that
**7 days**. That is fail2ban's `bantime * multipliers[earlier bans]` with
`bantime.multipliers = 1 24 168`, capped by `bantime.maxtime = 7d`.

Earlier bans are read from fail2ban's database, so escalation survives a
restart. **It only remembers as far back as `dbpurgeage`**, which defaults to
one day. Set it in `/etc/fail2ban/fail2ban.local` to the history you want, for
example `dbpurgeage = 30d`, or a second offence a week later will be treated
as a first.

The ban covers the relay's port and nothing else. The jail sets no action of
its own, so it uses your `[DEFAULT]` `banaction`. Check that this is a
port-scoped action (`fail2ban-client -d | grep remotedexter-relay` shows the
port in the rule), never an all-ports one, especially on a server you reach
over SSH.

### Carrier NAT and shared Wi-Fi

One public address can be many people: a mobile carrier's NAT, a campus, a café.
If a scanner shares an address with a real user, the ban shuts both out of the
relay for the ban's length. The trigger lines themselves can never come from
RemoteDexter, so this only happens to someone who happens to share an address
with a scanner. To lift a ban:

```bash
sudo fail2ban-client set remotedexter-relay unbanip <ip>
```

### The log lines a watcher may rely on

These formats are a contract. `crates/relay/src/logline.rs` is the only place
they are written, and `crates/relay/tests/fail2ban_contract.rs` fails if the
filter, the sample or the code drift apart. `<peer>` is `203.0.113.7:4242`, or
`[2001:db8::7]:4242` for IPv6.

```text
[relayd] <peer>: <reason>
[relayd] refused <peer>: <cap> connections already unauthenticated
[relayd] refused <n> more in the last <ms> ms: <cap> connections already unauthenticated
```

`<reason>` is one of the lines in the two tables above.

Refusals past the pending cap are **rate-limited**. The first after a quiet
second is logged with its peer; later ones are counted into a summary line, and
no two refusal lines are less than a second apart. Every refused connection is
in exactly one line: a per-peer line counts one, a summary counts `<n>`. One
line per refusal used to let a flood exceed journald's rate limit and drop the
very lines that would show it.

`<cap>` is currently 256, and it counts only connections that have **not yet
identified themselves**. A connection stops counting the moment its
registration succeeds, its join claims a session, or its attach redeems a
ticket; one that fails, or says nothing within 10 seconds of connecting or of
being challenged, is dropped and stops counting too. Registered hosts and live
sessions are bounded separately, by the session limit.

---

## What it costs to run

One long-lived TCP connection per registered host, plus two per active session.
No database, no disk state, no outbound connections. Memory is bounded by
construction: at most 64 concurrent sessions and 256 connections still
identifying themselves, both refused rather than queued when full. Each spliced connection's kernel buffers
are fixed at 128 KB.

A session that goes quiet is dropped: a host that stops answering the keepalive
loses its session within a minute, a socket that connects and says nothing is
closed after ten seconds, and a spliced session whose far side takes nothing
for 30 seconds is ended and its slot freed.

---

## Licence

AGPL-3.0-only, like the rest of RemoteDexter. If you run a **modified** relay as
a service for others, the licence requires you to offer them the source of your
modifications. Running an unmodified one for yourself or your own users carries
no such obligation.
