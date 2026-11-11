"""Tests for playbooks/files/parker_lib.py.

Run with: python3 -m pytest tests/
"""

import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "playbooks" / "files"))

import parker_lib  # noqa: E402

# wireguard keys: 42 base64 chars, one check char, one '='
PUBKEY = "A" * 43 + "="
PUBKEY2 = "Ag" + "A" * 40 + "E="
PUBKEY3 = "A" * 42 + "M="
NONCE = "0123456789abcdef0123456789abcdef"
POOL = "2a03:2260:3006:8000::/56"
# exactly two /64 pairs: only id 1 exists, id 2 is already past the end
SMALL_POOL = "2a03:2260:3006:c000::/62"


def pool_cfg(prefix=POOL):
    return {
        "prefix6": prefix,
        "range4": "10.80.96.0/22",
        "address4": "10.80.96.1",
        "mtu": 1406,
        "wg_keepalive": 25,
        "retry": 120,
        "concentrators": [
            {
                "id": 1,
                "pubkey": "B" * 42 + "E=",
                "endpoint": "01.example:10000",
                "address6": "2a03:2260:3006:8000::",
                "address4": "10.80.96.2",
                "uninteresting": "dropped",
            }
        ],
    }


@pytest.fixture
def repo(tmp_path):
    """A clone with a bare origin, like /etc/wireguard/peers-wg."""
    origin = tmp_path / "origin.git"
    work = tmp_path / "peers-wg"
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True
    )
    subprocess.run(["git", "clone", "-q", str(origin), str(work)], check=True)
    for key, value in (
        ("user.name", "auto"),
        ("user.email", "auto@example"),
        ("commit.gpgsign", "false"),
    ):
        subprocess.run(["git", "-C", str(work), "config", key, value], check=True)
    (work / "README").write_text("peers\n")
    subprocess.run(["git", "-C", str(work), "add", "README"], check=True)
    subprocess.run(["git", "-C", str(work), "commit", "-qm", "init"], check=True)
    subprocess.run(
        ["git", "-C", str(work), "push", "-q", "-u", "origin", "main"], check=True
    )
    return work


@pytest.fixture
def local_repo(tmp_path):
    """A registry without any remote, like /var/lib/parker/registry."""
    work = tmp_path / "registry"
    subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
    for key, value in (
        ("user.name", "auto"),
        ("user.email", "auto@example"),
        ("commit.gpgsign", "false"),
    ):
        subprocess.run(["git", "-C", str(work), "config", key, value], check=True)
    return work


def remote_log(work, branch="main"):
    return subprocess.run(
        ["git", "-C", str(work), "log", "--format=%s", f"origin/{branch}"],
        capture_output=True,
        check=True,
    ).stdout.decode().splitlines()


def run_but_fail_on(fail_on):
    """A subprocess.run lookalike that fails for git subcommands in fail_on."""

    def run(cmd, **kwargs):
        if any(arg in fail_on for arg in cmd):
            return subprocess.CompletedProcess(cmd, 1, b"", b"simulated failure")
        return subprocess.run(cmd, **kwargs)

    return run


# --- validation -------------------------------------------------------------


@pytest.mark.parametrize(
    "bad", ["", "short", "a" * 43, PUBKEY[:-2] + "a=", PUBKEY + "x"]
)
def test_validate_pubkey_rejects(bad):
    with pytest.raises(parker_lib.InvalidRequest):
        parker_lib.validate_pubkey(bad)


def test_validate_pubkey_and_nonce_accept():
    assert parker_lib.validate_pubkey(PUBKEY) == PUBKEY
    assert parker_lib.validate_nonce(NONCE) == NONCE
    with pytest.raises(parker_lib.InvalidRequest):
        parker_lib.validate_nonce("xyz")


# --- records ----------------------------------------------------------------


def test_record_roundtrip_ignores_extra_fields():
    text = parker_lib.format_record(PUBKEY, 412, [1, 2]) + "reviewed: yes\n"
    rec = parker_lib.parse_record(text)
    assert rec == {"pubkey": PUBKEY, "id": 412, "conc": [1, 2], "path": "parker"}


@pytest.mark.parametrize(
    "text",
    [
        "\n",
        "notapubkey\nid: 1\n",
        PUBKEY + "\n",
        PUBKEY + "\nid: twelve\n",
        PUBKEY + "\nid: 3\nconc: a,b\n",
    ],
)
def test_parse_record_rejects(text):
    with pytest.raises(parker_lib.RecordConflict):
        parker_lib.parse_record(text)


def test_load_records_detects_duplicates(repo):
    (repo / "parker").mkdir()
    (repo / "parker" / "k1").write_text(parker_lib.format_record(PUBKEY, 5, [1]))
    assert parker_lib.load_records(str(repo))[PUBKEY]["id"] == 5

    (repo / "parker" / "k2").write_text(parker_lib.format_record(PUBKEY, 6, [1]))
    with pytest.raises(parker_lib.RecordConflict, match="pubkey"):
        parker_lib.load_records(str(repo))

    (repo / "parker" / "k2").write_text(parker_lib.format_record(PUBKEY2, 5, [1]))
    with pytest.raises(parker_lib.RecordConflict, match="id"):
        parker_lib.load_records(str(repo))


def test_load_records_missing_dir(tmp_path):
    assert parker_lib.load_records(str(tmp_path)) == {}


def test_record_filename_is_filesystem_safe():
    weird = "ab+cd/efghijklmnopqrstuvwxyz0123456789012E="
    name = parker_lib.record_relpath(weird)
    assert "/" not in Path(name).name and "+" not in name
    assert name.startswith("parker/")


# --- id <-> prefix ----------------------------------------------------------


def test_pool_sizing():
    assert parker_lib.id_capacity("2a03:2260:3006::/48") == 32768
    assert parker_lib.id_capacity(POOL) == 128
    # growing to the surrounding /49 later is a config change, not a
    # migration: 2*id maps onto the same /64 in both
    assert parker_lib.id_capacity("2a03:2260:3006:8000::/49") == 16384
    assert parker_lib.id_capacity(SMALL_POOL) == 2


def test_id_to_prefixes_bijection():
    # an id owns two consecutive /64s of the pool; id 0 is reserved for infra,
    # so id 1 starts at the *second* pair of /64s of the pool
    assert parker_lib.id_to_prefixes(POOL, 1) == (
        "2a03:2260:3006:8002::/64",
        "2a03:2260:3006:8003::/64",
    )
    assert parker_lib.id_to_prefixes(POOL, 12) == (
        "2a03:2260:3006:8018::/64",
        "2a03:2260:3006:8019::/64",
    )
    with pytest.raises(parker_lib.PoolExhausted):
        parker_lib.id_to_prefixes(POOL, 0)
    with pytest.raises(parker_lib.PoolExhausted):
        parker_lib.id_to_prefixes(POOL, parker_lib.id_capacity(POOL))


def test_first_free_id_reuses_and_exhausts():
    assert parker_lib.first_free_id([], POOL) == 1
    assert parker_lib.first_free_id({1, 2, 4}, POOL) == 3
    with pytest.raises(parker_lib.PoolExhausted):
        parker_lib.first_free_id({1}, SMALL_POOL)


# --- config body -------------------------------------------------------------


def test_build_config_fields():
    conf = parker_lib.build_config(pool_cfg(), PUBKEY, 12, NONCE, now=1762000000)
    assert conf["id"] == PUBKEY
    assert conf["nonce"] == NONCE
    assert conf["time"] == 1762000000
    assert conf["range6"] == "2a03:2260:3006:8018::/64"
    assert conf["address6"] == "2a03:2260:3006:8018::1"
    assert conf["xlat_range6"] == "2a03:2260:3006:8019::/64"
    assert conf["range4"] == "10.80.96.0/22"
    assert conf["mtu"] == 1406
    assert conf["concentrators"] == [
        {
            "id": 1,
            "pubkey": "B" * 42 + "E=",
            "endpoint": "01.example:10000",
            "address6": "2a03:2260:3006:8000::",
            "address4": "10.80.96.2",
        }
    ]


def test_build_config_xlat_kill_switch():
    cfg = pool_cfg()
    cfg["xlat"] = False
    assert "xlat_range6" not in parker_lib.build_config(cfg, PUBKEY, 1, NONCE)


# --- rate limiting -----------------------------------------------------------


def test_rate_limiter_window_per_source():
    limiter = parker_lib.RateLimiter(burst=2, window=60, daily=4)
    t = 1000.0
    assert limiter.allow_new("1.2.3.4", now=t)
    assert limiter.allow_new("1.2.3.4", now=t)
    assert not limiter.allow_new("1.2.3.4", now=t)
    assert limiter.allow_new("5.6.7.8", now=t)  # other source unaffected
    assert not limiter.allow_new("1.2.3.4", now=t + 59)
    assert limiter.allow_new("1.2.3.4", now=t + 61)  # window passed


def test_rate_limiter_daily_cap():
    limiter = parker_lib.RateLimiter(burst=100, window=60, daily=2)
    t = 1000.0
    assert limiter.allow_new("a", now=t)
    assert limiter.allow_new("b", now=t)
    assert not limiter.allow_new("c", now=t)


# --- allocation --------------------------------------------------------------


def allocate(repo, pubkey, cfg=None, **kwargs):
    kwargs.setdefault("lock_path", str(repo.parent / "alloc.lock"))
    kwargs.setdefault("push_flag", str(repo.parent / "push.flag"))
    return parker_lib.get_or_allocate(str(repo), cfg or pool_cfg(), pubkey, **kwargs)


def test_allocate_creates_and_pushes(repo):
    rec = allocate(repo, PUBKEY)
    assert rec["id"] == 1 and rec["conc"] == [1]
    content = (repo / "parker" / parker_lib.sanitize_pubkey(PUBKEY)).read_text()
    assert content == parker_lib.format_record(PUBKEY, 1, [1])
    assert "parker: auto add id 1" in remote_log(repo)


def test_allocate_without_remote_keeps_the_commit_local(local_repo):
    # no pull, no push, no push flag: the registry never leaves the host
    rec = allocate(local_repo, PUBKEY, sync=False)
    assert rec["id"] == 1
    assert not (local_repo.parent / "push.flag").exists()
    assert allocate(local_repo, PUBKEY, sync=False)["id"] == 1  # idempotent
    log = subprocess.run(
        ["git", "-C", str(local_repo), "log", "--format=%s"],
        capture_output=True,
        check=True,
    ).stdout.decode().splitlines()
    assert log == ["parker: auto add id 1"]
    assert subprocess.run(
        ["git", "-C", str(local_repo), "remote"],
        capture_output=True,
        check=True,
    ).stdout == b""


def test_allocate_is_idempotent(repo):
    first = allocate(repo, PUBKEY)
    before = remote_log(repo)
    second = allocate(repo, PUBKEY)
    assert second["id"] == first["id"]
    assert remote_log(repo) == before  # no re-registration commit
    assert allocate(repo, PUBKEY2)["id"] == 2


def test_allocate_reuses_freed_id(repo):
    allocate(repo, PUBKEY)
    allocate(repo, PUBKEY2)
    subprocess.run(
        ["git", "-C", str(repo), "rm", "-q", "--", parker_lib.record_relpath(PUBKEY)],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "gc"], check=True)
    subprocess.run(["git", "-C", str(repo), "push", "-q"], check=True)
    assert allocate(repo, PUBKEY3)["id"] == 1


def test_allocate_exhaustion_creates_nothing(repo):
    allocate(repo, PUBKEY, cfg=pool_cfg(SMALL_POOL))
    with pytest.raises(parker_lib.PoolExhausted):
        allocate(repo, PUBKEY2, cfg=pool_cfg(SMALL_POOL))
    assert not (repo / "parker" / parker_lib.sanitize_pubkey(PUBKEY2)).exists()
    assert len(remote_log(repo)) == 2  # init + first allocation


def test_allocate_before_create_can_veto(repo):
    def veto(_pubkey):
        raise parker_lib.RateLimited("nope")

    with pytest.raises(parker_lib.RateLimited):
        allocate(repo, PUBKEY, before_create=veto)
    assert not (repo / "parker").exists()
    assert len(remote_log(repo)) == 1  # nothing was committed

    allocate(repo, PUBKEY, before_create=lambda p: None)  # allowed path creates


def test_allocate_push_failure_defers_answer_and_recovers(repo):
    flag = str(repo.parent / "push.flag")
    with pytest.raises(parker_lib.PushPending):
        allocate(repo, PUBKEY, run=run_but_fail_on({"push"}))
    assert Path(flag).exists()
    # committed locally so the id is not handed to a second node...
    assert (repo / "parker" / parker_lib.sanitize_pubkey(PUBKEY)).exists()
    # ...but the other gateway cannot see it yet
    assert "parker: auto add id 1" not in remote_log(repo)

    rec = allocate(repo, PUBKEY)  # next poll flushes the push, answers the same id
    assert rec["id"] == 1
    assert not Path(flag).exists()
    assert "parker: auto add id 1" in remote_log(repo)


def test_allocate_blocks_new_ids_while_push_pending(repo):
    with pytest.raises(parker_lib.PushPending):
        allocate(repo, PUBKEY, run=run_but_fail_on({"push"}))
    # while the flag exists and the remote is still down, no node is served
    with pytest.raises(parker_lib.GitError):
        allocate(repo, PUBKEY, run=run_but_fail_on({"push"}))
    with pytest.raises(parker_lib.GitError):
        allocate(repo, PUBKEY2, run=run_but_fail_on({"push"}))
    assert not (repo / "parker" / parker_lib.sanitize_pubkey(PUBKEY2)).exists()


def test_allocate_serialises_concurrent_same_key(repo):
    """Two workers racing on the same fresh key: one commit, both see the id."""
    results = []
    barrier = threading.Barrier(2)

    def call():
        barrier.wait()
        results.append(allocate(repo, PUBKEY))

    threads = [threading.Thread(target=call) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert {r["id"] for r in results} == {1}
    assert len([line for line in remote_log(repo) if line.startswith("parker:")]) == 1


# --- signing -----------------------------------------------------------------


def test_sign_message_takes_the_sig_line():
    seen = {}

    def run(cmd, **kwargs):
        seen["cmd"] = cmd
        sigfile = Path(cmd[cmd.index("-x") + 1])
        sigfile.write_text("untrusted comment: signed by key 00\nRVRnT3Sig\n")
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    assert parker_lib.sign_message("/nope/secret", b"{}\n", run=run) == "RVRnT3Sig"
    assert seen["cmd"][0] == "usign"
    assert seen["cmd"][seen["cmd"].index("-x") + 1].endswith(".sig")


def test_sign_message_names_the_tool_in_errors():
    def failing(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, b"", b"no key")

    with pytest.raises(parker_lib.SignError, match="signify-openbsd"):
        parker_lib.sign_message("/nope", b"x", binary="signify-openbsd", run=failing)


def test_sign_message_errors():
    def failing(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, b"", b"no key")

    with pytest.raises(parker_lib.SignError):
        parker_lib.sign_message("/nope", b"x", run=failing)

    def no_file(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    with pytest.raises(parker_lib.SignError):
        parker_lib.sign_message("/nope", b"x", run=no_file)

    def no_signature_line(cmd, **kwargs):
        Path(cmd[cmd.index("-x") + 1]).write_text("untrusted comment: signed by key 00\n")
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    with pytest.raises(parker_lib.SignError):
        parker_lib.sign_message("/nope", b"x", run=no_signature_line)


# --- status / GC input --------------------------------------------------------


def test_status_roundtrip_and_merge(tmp_path):
    (tmp_path / parker_lib.STATUS_SUBDIR).mkdir()
    (tmp_path / parker_lib.STATUS_SUBDIR / "sn01.tsv").write_text(
        parker_lib.format_status({PUBKEY: 20000, PUBKEY2: 19999})
    )
    (tmp_path / parker_lib.STATUS_SUBDIR / "sn02.tsv").write_text(
        parker_lib.format_status({PUBKEY: 20001})
    )
    merged = parker_lib.load_status(str(tmp_path))
    assert merged == {PUBKEY: 20001, PUBKEY2: 19999}


def test_record_age_days(repo):
    allocate(repo, PUBKEY)
    relpath = parker_lib.record_relpath(PUBKEY)
    age = parker_lib.record_age_days(
        subprocess.run, str(repo), relpath, now=time.time()
    )
    assert 0 <= age < 1
    assert parker_lib.record_age_days(subprocess.run, str(repo), "nope") is None
