#!/usr/bin/env python3
"""
hollowcomm.py -- the ONLY communications library used by Hollow Moon.

Project 2/3 adds DatagramHub and DatagramClient (AF_UNIX/SOCK_DGRAM,
SO_PASSCRED/SCM_CREDENTIALS), retaining the original Hub and Client for a
reproducible baseline via --transport stream. See README for both APIs.

Primitive : AF_UNIX / SOCK_STREAM sockets + asyncio (non-blocking, event-loop I/O)
Framing   : 4-byte big-endian length prefix, followed by a UTF-8 JSON object
Identity  : the *kernel* tells the hub which Linux user is on the other end of
            every connection (SO_PEERCRED).  The "from" field of a message is
            stamped by the hub, never trusted from the sender, so one player
            cannot impersonate another.  The client does the same check in the
            other direction (it verifies the hub runs as the moderator's uid).

Public API
----------
Server side (used by moderator.py):
    hub = Hub(path, allowed={uid: name}, on_connect=, on_message=, on_disconnect=)
    await hub.start() / await hub.stop()
    hub.send(name, msg)                  unicast        (1 -> 1)
    hub.multicast(group, msg)            multicast      (1 -> named subset)
    hub.broadcast(msg, exclude=())       broadcast      (1 -> everyone)
    hub.join(name, group) / hub.leave(name, group) / hub.members(group)
    hub.is_connected(name) / hub.connected()

Client side (used by player.py and bot.py):
    cli = Client(path, expect_uid=None)
    await cli.connect()
    await cli.send(type, **fields)       send one message to the hub
    msg = await cli.recv()               next message, or None when hub closed
    await cli.close()

A message is a plain dict with a "type" key.  The hub adds "from" (the sender's
name) and "seq" (a hub-wide increasing number, so everyone agrees on ordering).
"""
import asyncio
import json
import os
import socket
import struct

MAX_FRAME = 64 * 1024            # refuse absurdly large frames (DoS protection)
MAX_QUEUE = 500                  # per-peer outbound backlog before we cut them off
_HDR = struct.Struct("!I")
_CRED = struct.Struct("3i")      # struct ucred { pid_t pid; uid_t uid; gid_t gid; }


class ProtocolError(Exception):
    pass


# --------------------------------------------------------------------------
# Framing helpers (shared by both sides)
# --------------------------------------------------------------------------
def encode(msg):
    body = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME:
        raise ProtocolError("frame too large")
    return _HDR.pack(len(body)) + body


async def read_frame(reader):
    """Read exactly one framed message.  Raises IncompleteReadError at EOF."""
    (n,) = _HDR.unpack(await reader.readexactly(_HDR.size))
    if n > MAX_FRAME:
        raise ProtocolError("frame too large")
    obj = json.loads((await reader.readexactly(n)).decode("utf-8"))
    if not isinstance(obj, dict):
        raise ProtocolError("message must be an object")
    return obj


def peer_credentials(writer):
    """(pid, uid, gid) of the process at the other end, as reported by the kernel."""
    sock = writer.get_extra_info("socket")
    return _CRED.unpack(sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CRED.size))


# --------------------------------------------------------------------------
# Server side
# --------------------------------------------------------------------------
class Peer:
    """One connected player, as seen by the hub."""

    def __init__(self, name, uid, pid, writer):
        self.name, self.uid, self.pid, self.writer = name, uid, pid, writer
        self.groups = set()
        self.outq = asyncio.Queue()
        self.alive = True


class Hub:
    def __init__(self, path, allowed, on_connect=None, on_message=None, on_disconnect=None):
        self.path = path
        self.allowed = dict(allowed)             # uid -> player name
        self.on_connect, self.on_message, self.on_disconnect = on_connect, on_message, on_disconnect
        self.peers = {}                          # name -> Peer
        self.seq = 0
        self.server = None

    # ---- lifecycle ----
    async def start(self):
        try:
            os.unlink(self.path)                 # stale socket from a previous run
        except FileNotFoundError:
            pass
        self.server = await asyncio.start_unix_server(self._serve, path=self.path)
        os.chmod(self.path, 0o666)               # anyone may *connect*; SO_PEERCRED decides who may *play*

    async def stop(self):
        for p in list(self.peers.values()):
            self._drop(p)
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    # ---- addressing ----
    def join(self, name, group):
        if name in self.peers:
            self.peers[name].groups.add(group)

    def leave(self, name, group):
        if name in self.peers:
            self.peers[name].groups.discard(group)

    def members(self, group):
        return [p.name for p in self.peers.values() if group in p.groups]

    def is_connected(self, name):
        return name in self.peers

    def connected(self):
        return list(self.peers)

    # ---- delivery ----
    def _stamp(self, msg):
        self.seq += 1
        out = dict(msg)
        out["seq"] = self.seq
        return out

    def _enqueue(self, peer, frame):
        if peer.outq.qsize() >= MAX_QUEUE:       # a stuck reader must not stall the game
            self._drop(peer)
        else:
            peer.outq.put_nowait(frame)

    def send(self, name, msg):                   # unicast
        p = self.peers.get(name)
        if p:
            self._enqueue(p, encode(self._stamp(msg)))

    def multicast(self, group, msg, exclude=()):  # multicast
        frame = encode(self._stamp(msg))         # encoded ONCE, same seq for every receiver
        for p in list(self.peers.values()):
            if group in p.groups and p.name not in exclude:
                self._enqueue(p, frame)

    def broadcast(self, msg, exclude=()):        # broadcast
        frame = encode(self._stamp(msg))
        for p in list(self.peers.values()):
            if p.name not in exclude:
                self._enqueue(p, frame)

    # ---- connection handling (one coroutine pair per client, all concurrent) ----
    async def _serve(self, reader, writer):
        try:
            pid, uid, _gid = peer_credentials(writer)
        except OSError:
            writer.close()
            return
        name = self.allowed.get(uid)
        if name is None or name in self.peers:
            why = "not a registered player" if name is None else "already connected"
            try:
                writer.write(encode({"type": "refused", "text": why}))
                await writer.drain()
            finally:
                writer.close()
            return
        peer = Peer(name, uid, pid, writer)
        self.peers[name] = peer
        sender = asyncio.ensure_future(self._writer_loop(peer))
        try:
            if self.on_connect:
                await self.on_connect(peer)
            while True:
                msg = await read_frame(reader)
                msg["from"] = peer.name          # stamped by the hub: cannot be forged
                msg.pop("seq", None)
                if self.on_message:
                    await self.on_message(peer, msg)
        except (asyncio.IncompleteReadError, ConnectionError, ProtocolError, ValueError):
            pass                                 # client left, or spoke garbage: drop them
        finally:
            sender.cancel()
            self._drop(peer)
            if self.on_disconnect:
                await self.on_disconnect(peer)

    async def _writer_loop(self, peer):
        try:
            while True:
                frame = await peer.outq.get()
                peer.writer.write(frame)
                await peer.writer.drain()        # back-pressure is per player
        except (ConnectionError, asyncio.CancelledError):
            pass

    def _drop(self, peer):
        if self.peers.get(peer.name) is peer:
            del self.peers[peer.name]
        peer.alive = False
        try:
            peer.writer.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# Client side
# --------------------------------------------------------------------------
class Client:
    def __init__(self, path, expect_uid=None):
        self.path, self.expect_uid = path, expect_uid
        self.reader = self.writer = None

    async def connect(self):
        self.reader, self.writer = await asyncio.open_unix_connection(self.path)
        if self.expect_uid is not None:          # mutual authentication
            _pid, uid, _gid = peer_credentials(self.writer)
            if uid != self.expect_uid:
                self.writer.close()
                raise ProtocolError("socket is not owned by the moderator (uid %d) -- refusing" % uid)

    async def send(self, type, **fields):
        fields["type"] = type
        self.writer.write(encode(fields))
        await self.writer.drain()

    async def recv(self):
        try:
            return await read_frame(self.reader)
        except (asyncio.IncompleteReadError, ConnectionError):
            return None

    async def close(self):
        if self.writer:
            self.writer.close()

# --------------------------------------------------------------------------
# Project 2/3: alternate IPC transport -- UNIX DATAGRAM SOCKETS.
# The original stream Hub and Client above remain runnable with --transport stream
# for comparison. Datagram IPC is message-oriented, not a byte-stream framing hack.
# Each received packet carries SCM_CREDENTIALS supplied by the Linux kernel.
# --------------------------------------------------------------------------
import collections
import secrets
import time

MAX_PACKET = 4096                    # intentionally much smaller than stream MAX_FRAME
DATAGRAM_QUEUE_LIMIT = 100           # bound each recipient's pending outbound packets
DATAGRAM_INBOUND_LIMIT = 64          # prevent slow game logic from building an unbounded queue
RATE_PER_SEC = 12.0                 # accepted gameplay messages per player per second
RATE_BURST = 24.0                    # token bucket capacity
HEARTBEAT_INTERVAL = 3.0
HEARTBEAT_TIMEOUT = 12.0
_CREDENTIAL_SPACE = socket.CMSG_SPACE(_CRED.size)


def _packet(msg):
    raw = json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode("utf8")
    if len(raw) > MAX_PACKET:
        raise ProtocolError("datagram too large (%d > %d bytes)" % (len(raw), MAX_PACKET))
    return raw


def _decode_packet(raw):
    if len(raw) > MAX_PACKET:
        raise ProtocolError("datagram too large")
    obj = json.loads(raw.decode("utf8"))
    if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
        raise ProtocolError("packet must contain a string type")
    return obj


def _receive_with_kernel_credentials(sock):
    data, anc, flags, address = sock.recvmsg(MAX_PACKET + 1, _CREDENTIAL_SPACE)
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise ProtocolError("truncated packet / credentials")
    credentials = [
        _CRED.unpack(body[:_CRED.size])
        for level, kind, body in anc
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS
        and len(body) >= _CRED.size
    ]
    if len(credentials) != 1:
        raise ProtocolError("missing or ambiguous kernel credentials")
    return data, credentials[0], address


class DatagramPeer:
    def __init__(self, name, uid, pid, address):
        self.name, self.uid, self.pid, self.address = name, uid, pid, address
        self.groups = set()
        self.inbound = asyncio.Queue(maxsize=DATAGRAM_INBOUND_LIMIT)
        self.tokens, self.last_token_time = RATE_BURST, time.monotonic()
        self.last_seen = time.monotonic()
        self.task = None


class DatagramHub:
    """Message-oriented Hub with per-packet UID/PID verification.

    Hub API matches original Hub. The moderator never needs to parse sockets,
    handle credentials, choose recipients, or manage asyncio fd callbacks.
    """

    def __init__(self, path, allowed, on_connect=None, on_message=None, on_disconnect=None):
        self.path, self.allowed = path, dict(allowed)
        self.on_connect, self.on_message, self.on_disconnect = on_connect, on_message, on_disconnect
        self.peers = {}
        self.sock, self.loop = None, None
        self.seq = 0
        self.pending = collections.deque()
        self.pending_counts = collections.Counter()
        self.watchdog = None
        self.stats = collections.Counter()

    async def start(self):
        if not hasattr(socket, "SO_PASSCRED"):
            raise RuntimeError("DatagramHub requires Linux SO_PASSCRED")
        self.loop = asyncio.get_running_loop()
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.sock.bind(self.path)
        os.chmod(self.path, 0o666)       # identity is checked with kernel credentials
        self.loop.add_reader(self.sock.fileno(), self._readable)
        self.watchdog = asyncio.create_task(self._watchdog())

    async def stop(self):
        if self.watchdog:
            self.watchdog.cancel()
        if self.sock:
            self.loop.remove_reader(self.sock.fileno())
            self.loop.remove_writer(self.sock.fileno())
        tasks = []
        for peer in list(self.peers.values()):
            self._drop(peer)
            if peer.task:
                tasks.append(peer.task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self.sock:
            self.sock.close()
            self.sock = None
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def join(self, name, group):
        if name in self.peers:
            self.peers[name].groups.add(group)

    def leave(self, name, group):
        if name in self.peers:
            self.peers[name].groups.discard(group)

    def members(self, group):
        return [p.name for p in self.peers.values() if group in p.groups]

    def is_connected(self, name):
        return name in self.peers

    def connected(self):
        return list(self.peers)

    def _stamp(self, msg):
        self.seq += 1
        result = dict(msg)
        result["seq"] = self.seq
        return result

    def _try_send(self, peer, raw):
        try:
            self.sock.sendto(raw, peer.address)
            self.stats["sent"] += 1
            return True
        except BlockingIOError:
            return False
        except OSError:
            self.stats["send_errors"] += 1
            self._drop(peer)
            return True

    def _send_packet(self, peer, raw):
        if self.peers.get(peer.name) is not peer or not self.sock:
            return
        if self.pending_counts[peer.name] == 0 and self._try_send(peer, raw):
            return
        if self.pending_counts[peer.name] >= DATAGRAM_QUEUE_LIMIT:
            self.stats["slow_reader_drops"] += 1
            self._drop(peer)
            return
        self.pending.append((peer, raw))
        self.pending_counts[peer.name] += 1
        self.loop.add_writer(self.sock.fileno(), self._writable)

    def _writable(self):
        # Cap work per callback to give the game event loop a chance to run.
        for _ in range(min(32, len(self.pending))):
            peer, raw = self.pending[0]
            if self.peers.get(peer.name) is not peer:
                self.pending.popleft()
                self.pending_counts[peer.name] -= 1
                continue
            if not self._try_send(peer, raw):
                break
            self.pending.popleft()
            self.pending_counts[peer.name] -= 1
        if not self.pending and self.sock:
            self.loop.remove_writer(self.sock.fileno())

    def send(self, name, msg):
        peer = self.peers.get(name)
        if peer:
            self._send_packet(peer, _packet(self._stamp(msg)))

    def multicast(self, group, msg, exclude=()):
        raw = _packet(self._stamp(msg))  # one sequence number for all recipients
        for peer in list(self.peers.values()):
            if group in peer.groups and peer.name not in exclude:
                self._send_packet(peer, raw)

    def broadcast(self, msg, exclude=()):
        raw = _packet(self._stamp(msg))
        for peer in list(self.peers.values()):
            if peer.name not in exclude:
                self._send_packet(peer, raw)

    def _unauthorized_reply(self, address, text):
        # An unknown UID cannot join, but can receive a concise refusal.
        if address:
            try:
                self.sock.sendto(_packet({"type": "refused", "text": text}), address)
            except OSError:
                pass

    def _readable(self):
        for _ in range(32):
            try:
                raw, (pid, uid, _gid), address = _receive_with_kernel_credentials(self.sock)
            except BlockingIOError:
                break
            except (ProtocolError, OSError):
                self.stats["malformed"] += 1
                continue
            try:
                msg = _decode_packet(raw)
            except (ValueError, UnicodeError, ProtocolError):
                self.stats["malformed"] += 1
                continue
            name = self.allowed.get(uid)
            if name is None:
                self.stats["unauthorized"] += 1
                self._unauthorized_reply(address, "not a registered Linux user")
                continue
            peer = self.peers.get(name)
            if msg["type"] == "__hello__":
                if peer is None:
                    if not isinstance(address, str) or not address:
                        self.stats["malformed"] += 1
                        continue
                    peer = DatagramPeer(name, uid, pid, address)
                    self.peers[name] = peer
                    self.stats["connections"] += 1
                    self._send_packet(peer, _packet({"type": "__welcome__"}))
                    peer.task = asyncio.create_task(self._dispatch(peer))
                elif peer.pid != pid or peer.address != address:
                    self.stats["duplicate_rejected"] += 1
                    self._unauthorized_reply(address, "this Linux user already has a session")
                else:
                    peer.last_seen = time.monotonic()
                    self._send_packet(peer, _packet({"type": "__welcome__"}))
                continue
            if not peer or peer.pid != pid or peer.address != address:
                self.stats["spoof_rejected"] += 1
                continue
            peer.last_seen = time.monotonic()
            if msg["type"] == "__heartbeat__":
                self.stats["heartbeats"] += 1
                continue
            if msg["type"] == "__bye__":
                self._drop(peer)
                continue
            if msg["type"].startswith("__"):
                self.stats["malformed"] += 1
                continue
            now = time.monotonic()
            peer.tokens = min(RATE_BURST, peer.tokens + (now - peer.last_token_time) * RATE_PER_SEC)
            peer.last_token_time = now
            if peer.tokens < 1:
                self.stats["rate_limited"] += 1
                continue
            peer.tokens -= 1
            msg["from"] = name            # never believe client supplied from/seq
            msg.pop("seq", None)
            try:
                peer.inbound.put_nowait(msg)
                self.stats["received"] += 1
            except asyncio.QueueFull:
                self.stats["inbound_overflow"] += 1
                self._drop(peer)

    async def _dispatch(self, peer):
        try:
            if self.on_connect:
                await self.on_connect(peer)
            while self.peers.get(peer.name) is peer:
                msg = await peer.inbound.get()
                if self.on_message:
                    await self.on_message(peer, msg)
        except asyncio.CancelledError:
            pass
        finally:
            if self.on_disconnect:
                await self.on_disconnect(peer)

    def _drop(self, peer):
        if self.peers.get(peer.name) is peer:
            del self.peers[peer.name]
            self.stats["disconnections"] += 1
        # Do not retain stale packets/counts when this Linux user reconnects.
        if self.pending:
            self.pending = collections.deque((p, raw) for p, raw in self.pending if p is not peer)
            self.pending_counts[peer.name] = 0
            if not self.pending and self.sock:
                self.loop.remove_writer(self.sock.fileno())
        if peer.task and not peer.task.done():
            peer.task.cancel()

    async def _watchdog(self):
        try:
            while True:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                now = time.monotonic()
                for peer in list(self.peers.values()):
                    if now - peer.last_seen > HEARTBEAT_TIMEOUT:
                        self.stats["heartbeat_timeouts"] += 1
                        self._drop(peer)
        except asyncio.CancelledError:
            pass


class DatagramClient:
    """Client for DatagramHub. Every incoming packet must come from expected UID.

    The client socket lives in a sticky (1777) directory. Its pathname includes
    a random value; the server additionally authenticates UID+PID on every packet.
    """

    def __init__(self, path, expect_uid=None):
        self.path, self.expect_uid = path, expect_uid
        self.sock, self.loop = None, None
        self.local_path = None
        self.inbound = asyncio.Queue()
        self.heartbeat = None
        self.closed = False
        self.rejected_packets = 0

    async def connect(self):
        self.loop = asyncio.get_running_loop()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        directory = os.path.join(os.path.dirname(self.path), "clients")
        # setup_users.sh creates this shared sticky directory. Never use /tmp.
        self.local_path = os.path.join(directory, "p%d-%s.sock" % (os.getpid(), secrets.token_hex(6)))
        try:
            self.sock.bind(self.local_path)
            os.chmod(self.local_path, 0o666)
            self.sock.connect(self.path)
            self.loop.add_reader(self.sock.fileno(), self._readable)
            await self.loop.sock_sendall(self.sock, _packet({"type": "__hello__"}))
            reply = await asyncio.wait_for(self.inbound.get(), timeout=5)
            if not reply or reply.get("type") != "__welcome__":
                raise ProtocolError("moderator refused datagram connection: %s" % reply)
            self.heartbeat = asyncio.create_task(self._keepalive())
        except Exception:
            await self.close()
            raise

    def _readable(self):
        for _ in range(32):
            try:
                raw, (_pid, uid, _gid), _address = _receive_with_kernel_credentials(self.sock)
            except BlockingIOError:
                break
            except (ProtocolError, OSError):
                self.rejected_packets += 1
                continue
            if self.expect_uid is not None and uid != self.expect_uid:
                self.rejected_packets += 1
                continue
            try:
                msg = _decode_packet(raw)
            except (ValueError, UnicodeError, ProtocolError):
                self.rejected_packets += 1
                continue
            self.inbound.put_nowait(msg)

    async def _keepalive(self):
        try:
            while not self.closed:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                await self.send("__heartbeat__")
        except (asyncio.CancelledError, OSError):
            pass

    async def send(self, type, **fields):
        if self.closed or not self.sock:
            raise ConnectionError("datagram socket closed")
        msg = dict(fields)
        msg["type"] = type
        await self.loop.sock_sendall(self.sock, _packet(msg))

    async def recv(self):
        return await self.inbound.get()

    async def close(self):
        if self.closed:
            return
        if self.sock:
            try:
                await self.loop.sock_sendall(self.sock, _packet({"type": "__bye__"}))
            except OSError:
                pass
            if self.heartbeat:
                self.heartbeat.cancel()
            self.loop.remove_reader(self.sock.fileno())
            self.sock.close()
            self.sock = None
        if self.local_path:
            try:
                os.unlink(self.local_path)
            except FileNotFoundError:
                pass
        self.closed = True
        self.inbound.put_nowait(None)
