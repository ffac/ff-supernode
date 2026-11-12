"""Shared helpers for the parker config service.

Used by the ff.wgbroker broker (the /config endpoint and its garbage
collector) and by the ff.parker_concentrator reconciler. Kept in
playbooks/files/ so all three install the same copy.

The module is stdlib-only and free of Ansible templating so it can be
unit-tested as-is (tests/test_parker_lib.py). Every operation that runs a
subprocess takes an injectable ``run`` callable with the signature of
subprocess.run; the broker runs as the ``auto`` user directly, the
reconciler and the GC run as root and pass demote_runner() so that git
operations keep the ``auto`` identity.

Registry format, one file per parker node below ``REPO/parker/``::

    <base64 wireguard pubkey>
    id: 412
    conc: 1,2

The first line is a plain key like in the batman-side files, so
autoupdate_wg.py keeps ignoring these records: they live in a subdirectory
it never scans. The id maps to the node's delegated prefix pair
(range6 + xlat_range6) via id_to_prefixes(); it is allocated once and
never re-derived from the key.

The registry is a git repository of its own, not the batman peer list: the
two have different lifetimes and only one of them is rewritten by every
node poll. It may live without a remote (sync=False below), in which case
the commits are the local audit log and nothing leaves the host.
"""

import fcntl
import json
import os
import re
import subprocess
import tempfile
import threading
import time
import zlib
from ipaddress import IPv6Address, ip_network

PUBKEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
NODE_ID_RE = re.compile(r"^[0-9a-f]{12}$")

RECORDS_SUBDIR = "parker"
STATUS_SUBDIR = "parker-status"

# A delegated unit is one /64; every id owns range6 and the xlat sibling,
# so it consumes two of them. Public because the concentrator's reconciler
# needs it to tell its own routes from bird's in the shared table.
DELEGATION_BITS = 64


class ParkerError(Exception):
    """Base class for everything that can go wrong below."""


class InvalidRequest(ParkerError):
    """Malformed request (bad pubkey or nonce)."""


class PoolExhausted(ParkerError):
    """No free id in the parker prefix pool."""


class RecordConflict(ParkerError):
    """A record is malformed or claims an id/pubkey that is in use."""


class RateLimited(ParkerError):
    """Too many new nodes at once, try again later."""


class GitError(ParkerError):
    """A git operation failed."""


class PushPending(GitError):
    """The record is committed locally but not pushed: do not answer."""


class SignError(ParkerError):
    """usign failed or produced something unexpected."""


# ---------------------------------------------------------------------------
# validation


def validate_pubkey(pubkey):
    if not PUBKEY_RE.match(pubkey):
        raise InvalidRequest(f"not a wireguard public key: {pubkey!r}")
    return pubkey


def validate_nonce(nonce):
    if not NONCE_RE.match(nonce):
        raise InvalidRequest(f"not a 32 hex digit nonce: {nonce!r}")
    return nonce


# ---------------------------------------------------------------------------
# records


def sanitize_pubkey(pubkey):
    """Filename-safe form of a base64 key (+ -> -, / -> _, no padding)."""
    return pubkey.translate(str.maketrans("+/", "-_")).rstrip("=")


def record_relpath(pubkey):
    return os.path.join(RECORDS_SUBDIR, sanitize_pubkey(pubkey))


def format_record(pubkey, node_id, conc_ids):
    return f"{pubkey}\nid: {node_id}\nconc: {','.join(str(c) for c in conc_ids)}\n"


def parse_record(text, path=RECORDS_SUBDIR):
    """Parse one registry record. Extra fields are ignored on purpose."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise RecordConflict(f"{path}: empty record")

    pubkey = lines[0]
    if not PUBKEY_RE.match(pubkey):
        raise RecordConflict(f"{path}: {pubkey!r} is not a wireguard public key")

    node_id = None
    conc = []
    for line in lines[1:]:
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "id":
            try:
                node_id = int(value)
            except ValueError:
                raise RecordConflict(f"{path}: invalid id {value!r}") from None
        elif key == "conc":
            try:
                conc = [int(part) for part in re.split(r"[,\s]+", value) if part]
            except ValueError:
                raise RecordConflict(f"{path}: invalid conc {value!r}") from None

    if node_id is None:
        raise RecordConflict(f"{path}: missing id")
    return {"pubkey": pubkey, "id": node_id, "conc": conc, "path": path}


def load_records(repo_dir):
    """All parker records, keyed by pubkey. Raises on duplicate pubkey or id."""
    records = {}
    seen_ids = {}
    directory = os.path.join(repo_dir, RECORDS_SUBDIR)
    if not os.path.isdir(directory):
        return records
    for entry in sorted(os.scandir(directory), key=lambda e: e.name):
        if not entry.is_file() or entry.name.startswith("."):
            continue
        relpath = os.path.join(RECORDS_SUBDIR, entry.name)
        with open(entry.path, encoding="utf-8") as handle:
            record = parse_record(handle.read(), relpath)
        if record["pubkey"] in records:
            raise RecordConflict(
                f"{relpath}: pubkey also in {records[record['pubkey']]['path']}"
            )
        if record["id"] in seen_ids:
            raise RecordConflict(
                f"{relpath}: id {record['id']} also in {seen_ids[record['id']]}"
            )
        seen_ids[record["id"]] = relpath
        records[record["pubkey"]] = record
    return records


# ---------------------------------------------------------------------------
# id <-> prefix mapping


def _pool_network(prefix6):
    net = ip_network(prefix6)
    if net.prefixlen > DELEGATION_BITS:
        raise ValueError(f"{prefix6}: pool is smaller than one /{DELEGATION_BITS}")
    return net


def id_capacity(prefix6):
    """Number of ids the pool holds; ids 1..capacity-1 are allocatable, 0 is infra."""
    net = _pool_network(prefix6)
    return net.num_addresses // (2 ** (DELEGATION_BITS + 1))


def id_to_prefixes(prefix6, node_id):
    """Return (range6, xlat_range6) as /64 strings for one id.

    The mapping is a bijection over the pool: range6 is the 2*id-th /64 of
    the pool, xlat_range6 its sibling. Renumbering the pool is therefore a
    config change, not a migration of records.
    """
    net = _pool_network(prefix6)
    capacity = net.num_addresses // (2 ** DELEGATION_BITS)
    if node_id < 1 or 2 * node_id + 1 >= capacity:
        raise PoolExhausted(f"id {node_id} does not fit into {prefix6}")
    step = 2**DELEGATION_BITS
    base = int(net.network_address) + 2 * node_id * step
    return f"{IPv6Address(base)}/64", f"{IPv6Address(base + step)}/64"


def first_free_id(used_ids, prefix6):
    """Lowest free id in the pool, or PoolExhausted.

    First fit, so ids freed by the GC are reused. With auto-approval a
    monotonic cursor would turn unauthenticated spam into permanent prefix
    exhaustion.
    """
    used = set(used_ids)
    capacity = id_capacity(prefix6)
    for candidate in range(1, capacity):
        if candidate not in used:
            return candidate
    raise PoolExhausted(f"no free id below {capacity} in {prefix6}")


# ---------------------------------------------------------------------------
# config response body


def build_config(pool_cfg, pubkey, node_id, nonce, now=None):
    """The /config answer for one node, as a dict.

    pool_cfg holds the community-wide constants; the concentrator list is
    always sent in full so the node keeps a second tunnel and can fail over
    without being reflashed. The node caps mtu against its own WAN MTU
    (nodeconfig.lua), so the value here is the community maximum, not a
    per-link computation.
    """
    range6, xlat_range6 = id_to_prefixes(pool_cfg["prefix6"], node_id)
    address6 = node_address(range6)

    conf = {
        "nonce": nonce,
        "time": int(time.time() if now is None else now),
        "id": pubkey,
        "mtu": pool_cfg["mtu"],
        "wg_keepalive": pool_cfg["wg_keepalive"],
        "retry": pool_cfg["retry"],
        "range6": range6,
        "address6": address6,
        "range4": pool_cfg["range4"],
        "address4": pool_cfg["address4"],
        "concentrators": [
            {
                key: conc[key]
                for key in ("id", "pubkey", "endpoint", "address6", "address4")
            }
            for conc in pool_cfg["concentrators"]
        ],
    }
    # 464XLAT: without this field the node falls back to routed IPv4 in the
    # tunnel. Leaving it out is the documented per-node kill switch.
    if pool_cfg.get("xlat", True):
        conf["xlat_range6"] = xlat_range6
    return conf


# ---------------------------------------------------------------------------
# respondd


# The module list yanic asks for on a bat interface; a parker node answers the
# same request over its tunnel.
RESPOND_QUERY = b"GET nodeinfo statistics neighbours"
RESPOND_PORT = 1001


def node_address(range6):
    """The node's own address inside its delegated /64 - always ::1."""
    return str(ip_network(range6)[1])


def respondd_node_id(response):
    """The 12 hex digit node id from a decoded answer, or None.

    yanic accepts an answer only when every module that is present carries the
    same id, so a single module is enough to name the node.
    """
    for module in ("nodeinfo", "neighbours", "statistics"):
        section = response.get(module)
        if isinstance(section, dict):
            node_id = section.get("node_id")
            if isinstance(node_id, str) and NODE_ID_RE.match(node_id):
                return node_id
    return None


def parse_respondd(payload):
    """Decode one respondd answer: raw deflate, JSON object, valid node id.

    The node answers in exactly the format yanic's own collector produces, so
    the concentrator forwards the payload unchanged. Decoding here only keeps
    junk out of the monitor's log and tells us which node stayed silent.
    """
    try:
        response = json.loads(zlib.decompress(payload, -zlib.MAX_WBITS))
    except (zlib.error, ValueError) as exc:
        raise ParkerError(f"not a deflated JSON answer: {exc}") from None
    if not isinstance(response, dict):
        raise ParkerError("answer is not a JSON object")
    if respondd_node_id(response) is None:
        raise ParkerError("answer carries no 12 digit node id")
    return response


# ---------------------------------------------------------------------------
# subprocess plumbing


def demote_runner(user="auto"):
    """A subprocess.run lookalike that drops privileges before exec.

    Needed by the root-run cron scripts; the broker already runs as user.
    """
    import pwd

    pw = pwd.getpwnam(user)

    def demote():
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)

    def run(cmd, **kwargs):
        return subprocess.run(cmd, preexec_fn=demote, **kwargs)

    return run


def git(run, repo, *args, check=True):
    proc = run(["git", "-C", repo, *[str(a) for a in args]], capture_output=True)
    if check and proc.returncode != 0:
        raise GitError(
            "git "
            + " ".join(str(a) for a in args)
            + f": exit {proc.returncode}: "
            + proc.stderr.decode(errors="replace").strip()
        )
    return proc


class AllocationLock:
    """Advisory lock so concurrent /config requests allocate one id each."""

    def __init__(self, path):
        self.path = path
        self._handle = None

    def __enter__(self):
        self._handle = open(self.path, "a+")
        fcntl.flock(self._handle, fcntl.LOCK_EX)
        return self

    def __exit__(self, *_exc):
        fcntl.flock(self._handle, fcntl.LOCK_UN)
        self._handle.close()
        self._handle = None


# ---------------------------------------------------------------------------
# allocation


def get_or_allocate(
    repo_dir,
    pool_cfg,
    pubkey,
    *,
    run=subprocess.run,
    lock_path=None,
    push_flag=None,
    before_create=None,
    sync=True,
):
    """Return the record for pubkey, creating and pushing one if it is new.

    Ordering matters: once the answer carries a prefix, a lost push means
    the next node gets the same /63. So the record is committed and pushed
    *before* the caller is allowed to answer; anything else raises and the
    node retries on its next poll.

    A push failure leaves a record behind that the next gateway will never
    learn about from the remote. It is kept (the local concentrator already
    serves it) but flagged; while the flag exists no further allocation
    happens and every call retries the push first.

    sync=False is for a registry that only exists on this host: no pull, no
    push, no push flag. The commit stays local, which keeps the ordering
    guarantee trivially - there is nothing that can be lost on the way out.

    before_create(pubkey) is called once per new node under the lock; the
    broker passes its rate limiter here.
    """
    if lock_path is None:
        lock_path = os.path.join(tempfile.gettempdir(), "ff-parker-allocate.lock")

    with AllocationLock(lock_path):
        if sync:
            if push_flag and os.path.exists(push_flag):
                # A previous allocation is committed but unpushed. Answering
                # more nodes before that lands doubles out the concentrators.
                git(run, repo_dir, "push")
                os.remove(push_flag)

            git(run, repo_dir, "pull", "--ff-only")
        records = load_records(repo_dir)

        record = records.get(pubkey)
        if record is not None:
            return record

        if before_create is not None:
            before_create(pubkey)

        node_id = first_free_id(
            (rec["id"] for rec in records.values()), pool_cfg["prefix6"]
        )
        conc = [conc["id"] for conc in pool_cfg["concentrators"]]
        relpath = record_relpath(pubkey)
        fullpath = os.path.join(repo_dir, relpath)
        os.makedirs(os.path.dirname(fullpath), exist_ok=True)

        tmp = fullpath + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.write(format_record(pubkey, node_id, conc))
        os.rename(tmp, fullpath)

        git(run, repo_dir, "add", "--", relpath)
        git(run, repo_dir, "commit", "-m", f"parker: auto add id {node_id}")
        if sync:
            try:
                git(run, repo_dir, "push")
            except GitError as exc:
                if push_flag:
                    with open(push_flag, "w", encoding="utf-8") as handle:
                        handle.write(f"{pubkey} id {node_id}\n")
                raise PushPending(
                    f"record for {pubkey} committed but not pushed"
                ) from exc

    return {"pubkey": pubkey, "id": node_id, "conc": conc, "path": relpath}


# ---------------------------------------------------------------------------
# rate limiting


class RateLimiter:
    """Sliding window per source plus a cap on new nodes per day.

    The /config endpoint is unauthenticated and, unlike the batman side,
    every accepted new node consumes a routed prefix. The limits make spam
    annoying instead of damaging; the GC gives the burnt ids back.
    """

    def __init__(self, burst=10, window=3600, daily=200):
        self.burst = burst
        self.window = window
        self.daily = daily
        self._per_source = {}
        self._today = []
        self._lock = threading.Lock()

    def allow_new(self, key, now=None):
        now = time.time() if now is None else now
        with self._lock:
            self._today = [t for t in self._today if t > now - 86400]
            if len(self._today) >= self.daily:
                return False
            seen = [t for t in self._per_source.get(key, []) if t > now - self.window]
            if len(seen) >= self.burst:
                self._per_source[key] = seen
                return False
            seen.append(now)
            self._per_source[key] = seen
            self._today.append(now)
            return True


# ---------------------------------------------------------------------------
# signing


def sign_message(secret_path, message, *, binary="usign", run=subprocess.run):
    """Detached usign signature over message (bytes) as a single line.

    nodeconfig.sh splits the response at the last line and verifies
    everything before it, so exactly one signature line must come back.
    ``binary`` names the signing tool; Debian's signify-openbsd writes the
    same format and accepts the same flags.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        msgfile = os.path.join(tmpdir, "message")
        sigfile = os.path.join(tmpdir, "message.sig")
        with open(msgfile, "wb") as handle:
            handle.write(message)
        # The tool writes the detached signature to <msgfile>.sig and prints
        # nothing, so name the file explicitly and read it back.
        proc = run(
            [binary, "-S", "-m", msgfile, "-s", secret_path, "-x", sigfile],
            capture_output=True,
        )
        if proc.returncode != 0:
            raise SignError(
                f"{binary}: exit "
                f"{proc.returncode}: "
                + proc.stderr.decode(errors="replace").strip()
            )
        try:
            with open(sigfile, encoding="utf-8") as handle:
                siglines = handle.read().splitlines()
        except OSError as exc:
            raise SignError(f"{binary} wrote no signature file: {exc}") from exc
        sigs = [
            line
            for line in siglines
            if line.strip() and not line.startswith("untrusted comment")
        ]
        if len(sigs) != 1:
            raise SignError(f"{binary} produced {len(sigs)} signature lines")
        return sigs[0]


# ---------------------------------------------------------------------------
# gateway status files (GC input)


def status_relpath(hostname):
    return os.path.join(STATUS_SUBDIR, f"{hostname}.tsv")


def format_status(samples):
    """One day-bucket per line: <pubkey>\\t<last_handshake // 86400>.

    Buckets instead of timestamps so an active fleet only changes the file
    once a day and publishing it does not spam the repo.
    """
    return "".join(f"{pk}\t{bucket}\n" for pk, bucket in sorted(samples.items()))


def load_status(repo_dir):
    """Merge the per-gateway status files, newest day-bucket per pubkey."""
    merged = {}
    directory = os.path.join(repo_dir, STATUS_SUBDIR)
    if not os.path.isdir(directory):
        return merged
    for entry in sorted(os.scandir(directory), key=lambda e: e.name):
        if not entry.is_file() or not entry.name.endswith(".tsv"):
            continue
        with open(entry.path, encoding="utf-8") as handle:
            for line in handle:
                pubkey, _, bucket = line.strip().partition("\t")
                if pubkey and bucket.isdigit():
                    merged[pubkey] = max(merged.get(pubkey, 0), int(bucket))
    return merged


def record_age_days(run, repo_dir, relpath, now=None):
    """Days since the record was first committed, or None if unknown."""
    proc = git(
        run, repo_dir, "log", "--diff-filter=A", "--format=%ct", "--", relpath, check=False
    )
    stamps = proc.stdout.decode().split()
    if proc.returncode != 0 or not stamps:
        return None
    return ((time.time() if now is None else now) - int(stamps[0])) / 86400
