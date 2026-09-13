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

If `RD_RELAY` is set but the rest is wrong, the host says so on stderr and
offers no relay button. A misconfigured relay must not look identical to one
that was never configured.

The console then offers **Connect via relay**. A host connected this way **binds
nothing** — it holds one outbound control connection and opens a second
connection per client, on demand. The console says so: *"Reachable through relay
… — nothing is listening here."*

Its pairing code is a **v5 invite**, naming the relay and the session id rather
than an address. It is signed exactly as a direct invite is, and it carries the
same pinned host key.

---

## What it costs to run

One long-lived TCP connection per registered host, plus two per active session.
No database, no disk state, no outbound connections. Memory is bounded by
construction: at most 64 concurrent sessions and 256 connections awaiting
authentication, both refused rather than queued when full.

A session that goes quiet is dropped: a host that stops answering the keepalive
loses its session within a minute, and a socket that connects and says nothing
is closed after ten seconds.

---

## Licence

AGPL-3.0-only, like the rest of RemoteDexter. If you run a **modified** relay as
a service for others, the licence requires you to offer them the source of your
modifications. Running an unmodified one for yourself or your own users carries
no such obligation.
