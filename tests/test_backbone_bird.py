"""ff.backbone: the raw BIRD configs in files/bird/ must parse.

The role copies these files verbatim (common + profile + host), so the
concatenation in the order bird's include glob produces it is exactly
what bird will load. Syntax check with `bird -p`; the binary is taken
from $BIRD_BIN or PATH and the parse tests are skipped if absent.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROLE = Path(__file__).resolve().parent.parent / "playbooks/roles/ff.backbone"
BIRD_FILES = ROLE / "files/bird"
INVENTORY = ROLE.parents[2] / "inventory"
BIRD_BIN = os.environ.get("BIRD_BIN") or shutil.which("bird")

# host groups whose members run ff.backbone
PROFILE_GROUPS = ["backbone", "supernodes"]


def inventory_hosts():
    """Host -> bird profile, from the inventory's group trees.

    Ansible lets the deeper group win, so children override their
    parent's profile; the profile itself is read from that group's
    group_vars and the mapping fails loudly if it ever moves.
    """
    inv = yaml.safe_load(INVENTORY.read_text())
    group_vars = INVENTORY.parent / "group_vars"

    def profile_of(name):
        return yaml.safe_load((group_vars / name / "main.yml").read_text())["bird_profile"]

    hosts = {}
    for root in PROFILE_GROUPS:
        tree = inv[root]
        own = profile_of(root)
        for h in tree.get("hosts") or {}:
            hosts[h] = own
        for child in tree.get("children") or {}:
            for h in (inv.get(child) or {}).get("hosts") or {}:
                hosts[h] = profile_of(child)
    return hosts


HOSTS = inventory_hosts()


def layers(host, profile):
    return (
        sorted((BIRD_FILES / "common").glob("*.conf")),
        sorted((BIRD_FILES / profile).glob("*.conf")),
        sorted((BIRD_FILES / "hosts" / host).glob("*.conf")),
    )


def test_master_config_includes_ffac():
    master = (BIRD_FILES / "bird.conf").read_text()
    assert 'include "/etc/bird/ffac/*.conf";' in master


def test_no_templates_left():
    assert not (ROLE / "templates").exists()


def test_host_directories_match_inventory():
    on_disk = {p.name for p in (BIRD_FILES / "hosts").iterdir() if p.is_dir()}
    assert on_disk == set(HOSTS)


@pytest.mark.parametrize("host,profile", sorted(HOSTS.items()))
def test_layers_exist(host, profile):
    common, prof, own = layers(host, profile)
    assert common, "common layer is empty"
    assert prof, f"profile layer {profile} is empty"
    assert own, f"host layer for {host} is empty"


@pytest.mark.parametrize("host,profile", sorted(HOSTS.items()))
def test_layer_basenames_are_unique(host, profile):
    # ansible copy and the concatenation below both overwrite silently —
    # two layers must never ship the same filename
    names = [f.name for layer in layers(host, profile) for f in layer]
    assert len(names) == len(set(names)), f"colliding basenames for {host}"


@pytest.mark.parametrize("host,profile", sorted(HOSTS.items()))
def test_host_file_has_router_id(host, profile):
    _, _, own = layers(host, profile)
    text = "".join(f.read_text() for f in own)
    assert "router id" in text


def test_no_jinja_left():
    for pattern in ["{{", "{%", "{#"]:
        for f in BIRD_FILES.rglob("*.conf"):
            assert pattern not in f.read_text(), f"{pattern} in {f}"


@pytest.mark.parametrize("host,profile", sorted(HOSTS.items()))
def test_bird_parses(tmp_path, host, profile):
    if not BIRD_BIN:
        pytest.skip("bird binary not found (set $BIRD_BIN)")
    cfg_dir = tmp_path / "ffac"
    cfg_dir.mkdir()
    parts = [f for layer in layers(host, profile) for f in layer]
    # bird resolves include globs in glob(3) order: byte-wise sorted
    for f in sorted(parts, key=lambda p: p.name):
        shutil.copy(f, cfg_dir / f.name)
    master = tmp_path / "bird.conf"
    master.write_text(f'include "{cfg_dir}/*.conf";\n')
    proc = subprocess.run(
        [BIRD_BIN, "-p", "-c", str(master)], capture_output=True, text=True
    )
    errors = [
        line
        for line in proc.stderr.splitlines()
        if "Inferring" not in line and line.strip()
    ]
    assert proc.returncode == 0, "\n".join(errors)
    assert not errors
