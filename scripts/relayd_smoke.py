"""Drive the SHIPPED relayd binary from outside the process, over real sockets.

WHY THIS IS NOT A RUST TEST. Every other proof of the relay speaks the wire
format through the same `serde` derives that produce it, so a change to the
grammar changes both sides at once and no test notices. This reader is written
in another language against the format as DOCUMENTED -- a 4-byte big-endian
length followed by JSON with a "t" tag -- so a rename, a re-tag or an encoding
change fails here and nowhere else. The phone is the other reader that cannot be
kept in step automatically, which is exactly the class of defect this is for.

It also exercises the shipped BINARY rather than the library: its argument
handling, its accept loop, its logging and its shutdown.
"""
import json, socket, struct, subprocess, sys, time, os, signal

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RELAYD = os.path.join(ROOT, "target", "debug", "relayd")

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def send(sock, obj):
    body = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(body)) + body)

def recv(sock, timeout=5.0):
    sock.settimeout(timeout)
    hdr = b""
    while len(hdr) < 4:
        c = sock.recv(4 - len(hdr))
        if not c: raise EOFError("closed while reading length")
        hdr += c
    n = struct.unpack(">I", hdr)[0]
    body = b""
    while len(body) < n:
        c = sock.recv(n - len(body))
        if not c: raise EOFError("closed while reading body")
        body += c
    return json.loads(body)

port = free_port()
env = dict(os.environ,
           RD_RELAY_BIND=f"127.0.0.1:{port}",
           RD_RELAY_AUTH="bearer",
           RD_RELAY_TOKENS="smoke-token")
proc = subprocess.Popen([RELAYD], cwd=ROOT, env=env,
                        stderr=subprocess.PIPE, text=True)
time.sleep(1.0)
if proc.poll() is not None:
    print("relayd exited immediately:", proc.stderr.read()); sys.exit(1)

try:
    # 1. the host's control connection
    control = socket.create_connection(("127.0.0.1", port))
    send(control, {"t": "register", "v": 1, "host_pub": "smoke-token"})
    got = recv(control)
    assert got["t"] == "registered", got
    session = got["session"]
    print("  host registered, session id received (not printed)")

    # 2. a client asks for that session
    client = socket.create_connection(("127.0.0.1", port))
    send(client, {"t": "join", "v": 1, "session": session})

    # 3. the host is told, on the control connection
    told = recv(control)
    assert told["t"] == "client_waiting", told
    ticket = told["ticket"]
    print("  host told a client is waiting, with a ticket")

    # 4. the host dials back
    data = socket.create_connection(("127.0.0.1", port))
    send(data, {"t": "attach", "v": 1, "ticket": ticket})
    assert recv(data)["t"] == "attached"
    print("  host dialled back and was attached")

    # 5. only now is the client confirmed
    assert recv(client)["t"] == "joined"
    print("  client confirmed AFTER the data path existed")

    # 6. bytes cross, opaque to the relay
    data.sendall(b"host->phone")
    client.settimeout(5.0)
    assert client.recv(11) == b"host->phone"
    client.sendall(b"phone->host")
    data.settimeout(5.0)
    assert data.recv(11) == b"phone->host"
    print("  bytes crossed both ways through the splice")

    # 7. a spent ticket opens nothing
    replay = socket.create_connection(("127.0.0.1", port))
    send(replay, {"t": "attach", "v": 1, "ticket": ticket})
    r = recv(replay)
    assert r["t"] == "denied", r
    print(f"  a replayed ticket was refused: {r['why']!r}")

    # 8. reconnection: the first client goes, a second uses the SAME id
    client.close(); data.close()
    time.sleep(0.5)
    again = socket.create_connection(("127.0.0.1", port))
    send(again, {"t": "join", "v": 1, "session": session})
    told2 = recv(control)
    assert told2["t"] == "client_waiting", told2
    data2 = socket.create_connection(("127.0.0.1", port))
    send(data2, {"t": "attach", "v": 1, "ticket": told2["ticket"]})
    assert recv(data2)["t"] == "attached"
    assert recv(again)["t"] == "joined"
    print("  the SAME session id served a second client after the first left")

finally:
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill(); print("relayd did NOT stop on SIGTERM"); sys.exit(1)
    print(f"  relayd stopped on SIGTERM, exit {proc.returncode}")
    for line in (proc.stderr.read() or "").strip().splitlines():
        print("   ", line)

# Last, so the gate's one-line summary is this and not a log echo.
print("relayd smoke: PASSED — the shipped binary served a full session, refused a "
      "replayed ticket, and served the same session id again after the first client left")
