import glob
import json
import os
import pwd
import re
import subprocess
import unicodedata

from pathlib import Path

import parker_lib
from flask import Flask, Response, jsonify, request


REPO = "/etc/wireguard/peers-wg"

# The parker records live in a registry of their own, not in the batman peer
# list above. Empty remote = local only: no pull, no push, the commits on
# this host are the audit log.
PARKER_REPO = {{ wgbroker_parker_repo | tojson }}
PARKER_REPO_REMOTE = {{ wgbroker_parker_repo_remote | default("") | tojson }}

# Parker config service: community constants and concentrator list from
# group/host vars, null disables the /config endpoint. See
# playbooks/files/parker_lib.py.
# (Double tojson: the config arrives as one JSON string literal, since
# tojson's true/false/null are not python literals.)
# usign_secret is key content, not runtime config: drop it so the key never
# lands in this readable file; the broker signs with PARKER_SIGN_KEY below.
{% set _parker = (wgbroker_parker | default({}, true)) | dict2items
                 | rejectattr("key", "equalto", "usign_secret") | items2dict %}
PARKER = json.loads({{ _parker | tojson | tojson }})

# The role writes the signing key to this path (owner auto, mode 0600).
PARKER_SIGN_KEY = {{ wgbroker_parker_secret_key | tojson }}
PARKER_SIGNER = {{ wgbroker_parker_signer | tojson }}

app = Flask(__name__)
# TODO(ruairi): Refactor load_config to return Dataclass.

WG_PUBKEY_PATTERN = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")

_parker_cfg = PARKER if PARKER and PARKER.get("enabled") else None
_parker_limiter = None
if _parker_cfg:
    _limits = _parker_cfg.get("rate_limit", {})
    _parker_limiter = parker_lib.RateLimiter(
        burst=_limits.get("burst", 10),
        window=_limits.get("window", 3600),
        daily=_limits.get("daily", 200),
    )

# https://gist.github.com/berlotto/6295018
_slugify_strip_re = re.compile(r'[^\w\s-]')
_slugify_hyphenate_re = re.compile(r'[-\s]+')
def slugify(value):
    """
    Normalizes string, converts to lowercase, removes non-alpha characters,
    and converts spaces to hyphens.

    From Django's "django/template/defaultfilters.py".
    """
    value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
    value = _slugify_strip_re.sub('', value).strip().lower()
    return _slugify_hyphenate_re.sub('-', value)

def demote(user_uid, user_gid):
    def result():
        print(f"{user_uid}:{user_gid}")
        os.setgid(user_gid)
        os.setuid(user_uid)
    return result

def execute_autouser(cmd):
    # WARNING this is NOT threadsafe.
    autouser='auto'
    pw_record = pwd.getpwnam(autouser)
    homedir = pw_record.pw_dir
    user_uid = pw_record.pw_uid
    user_gid = pw_record.pw_gid
    env = os.environ.copy()
    env.update({'HOME': homedir, 'LOGNAME': autouser, 'USER': autouser})

    s = subprocess.run([cmd], shell=True, env=env,
                       preexec_fn=demote(user_uid, user_gid),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if s.returncode != 0:
        # Before the reply carried allocated prefixes a lost commit or push
        # was invisible and harmless; the node would just retry. Surface it
        # in the response instead of answering "OK" regardless.
        raise RuntimeError(f"{cmd}: exit {s.returncode}: "
                           + s.stderr.decode(errors='replace').strip())
    return s

def push_repo():
    execute_autouser(f"git -C {REPO} push")

def pull_repo():
    execute_autouser(f"git -C {REPO} pull")

def commit_repo(filename):
    execute_autouser(f"git -C {REPO} add {REPO}/{filename}")
    execute_autouser(f'git -C {REPO} commit -m "auto add new key: {filename}"')

def precheck(filename, publickey):
    if WG_PUBKEY_PATTERN.match(publickey) is None:
        raise ValueError(f"Not a valid Wireguard public key: {publickey}.")

    pattern = f"{REPO}/**/{filename}"
    for fname in glob.glob(pattern, recursive=True):
        if os.path.isfile(fname):
            raise Exception(f'{filename} already exists')

def remove_existing_key(filename, publickey):
    for file in Path(REPO).rglob('*'):
        if file.name == filename:
            continue
        if file.is_dir():
            continue
        if '.git' in file.relative_to(REPO).parts:
            continue
        with file.open('r') as keyonrecord:
            keyonrecord = keyonrecord.read()
            if publickey.strip() == keyonrecord.strip():
                file.unlink()
                execute_autouser(f"git -C {REPO} add {file}")

def add_file(filename, publickey):
    execute_autouser(f"echo {publickey} > {REPO}/{filename}")


@app.route("/api/add_key", methods=["POST"])
def add_key():
    try:
        data = request.get_json(force=True)
        print(f"adding key: {data}")
        if not data.get('node_name'):
            raise Exception(f'node_name missing {data}')
        if not data.get('public_key'):
            raise Exception(f'public_key missing {data}')
        filename = slugify(f"{data['node_name']}_{data['public_key'][:4]}")
        precheck(filename, data['public_key'])
        execute_autouser(f"git -C {REPO} reset --hard origin/main")
        pull_repo()
        remove_existing_key(filename, data['public_key'])
        add_file(filename, data['public_key'])
        commit_repo(filename)
        push_repo()
    except Exception as e:
        error_msg = f'Error adding key: {e}'
        print(error_msg)
        return jsonify({"Message": error_msg}), 200

    return jsonify({"Message": "OK"}), 200


def _parker_error(message, status):
    # nodeconfig.sh retries on any failed fetch; a plain status code is all
    # the node reads, the body is for journalctl.
    app.logger.warning(f"parker /config {status}: {message}")
    return Response(f"{message}\n", status=status, content_type="text/plain")


@app.route("/config", methods=["GET"])
def parker_config():
    """Introduce a parker node and hand it its delegated prefixes.

    Query parameters as sent by nodeconfig.sh: pubkey, nonce, v6mtu,
    version and optionally tc_ingress/tc_egress. The response is the JSON
    config followed by a newline and one detached usign signature line;
    the node verifies it against site.parker.config_pubkey.
    """
    if _parker_cfg is None:
        return _parker_error("parker config service disabled", 404)

    try:
        pubkey = parker_lib.validate_pubkey(request.args.get("pubkey", "").strip())
        nonce = parker_lib.validate_nonce(request.args.get("nonce", ""))
    except parker_lib.InvalidRequest as exc:
        return _parker_error(str(exc), 400)

    app.logger.info(
        "parker /config from %s: version=%s v6mtu=%s tc=%s/%s",
        request.remote_addr,
        request.args.get("version"),
        request.args.get("v6mtu"),
        request.args.get("tc_ingress"),
        request.args.get("tc_egress"),
    )

    def rate_limit(new_pubkey):
        source = request.remote_addr or "unknown"
        if not _parker_limiter.allow_new(source):
            raise parker_lib.RateLimited(
                f"allocation limit reached for {source}"
            )

    try:
        record = parker_lib.get_or_allocate(
            PARKER_REPO,
            _parker_cfg,
            pubkey,
            lock_path=_parker_cfg.get("lock_path", "/home/auto/.parker-allocation.lock"),
            push_flag=_parker_cfg.get("push_flag", "/home/auto/.parker-push-pending"),
            before_create=rate_limit,
            sync=bool(PARKER_REPO_REMOTE),
        )
        conf = parker_lib.build_config(_parker_cfg, pubkey, record["id"], nonce)
        body = json.dumps(conf, separators=(",", ":")) + "\n"
        signature = parker_lib.sign_message(
            PARKER_SIGN_KEY, body.encode("utf-8"), binary=PARKER_SIGNER
        )
    except parker_lib.RateLimited as exc:
        return _parker_error(str(exc), 429)
    except parker_lib.PushPending:
        # Committed here but not on the git server: the second gateway
        # would not program this prefix. Retry the push on the next poll.
        return _parker_error("registry not in sync, retrying", 503)
    except (parker_lib.PoolExhausted, parker_lib.RecordConflict) as exc:
        return _parker_error(f"parker registry: {exc}", 503)
    except parker_lib.GitError as exc:
        return _parker_error(f"registry unavailable: {exc}", 503)
    except parker_lib.SignError as exc:
        return _parker_error(f"signing failed: {exc}", 500)

    return Response(
        body + signature + "\n", status=200, content_type="text/plain; charset=utf-8"
    )


#@app.route("/api/del_key", methods=["POST"])
def del_key():
    data = request.get_json(force=True)
    if not data.get('node_name'):
        raise Exception('node_name missing')
    pull_repo()

    filename = data['node_name']
    execute_autouser("rm {filename}")
    commit_repo(slugify(filename))

@app.route("/", methods=["GET"])
def home():
    return '''
<html>
   <body>
       <div center style="width: 60%; margin: auto; height: 80%" >
        <h1>Freifunk Wireguard Key Broker</h1>
        <form id="key_form" action = "/api/add_key" method="POST" style="display: flex;flex-direction: column;">
            <span style="margin-bottom: 20px;">
                <label for="node_name">Node Name</label><br>
                <input type="string" style="width: 100%;" id="node_name" name="node_name" value="" />
            </span>
            <span style="margin-bottom: 20px;">
                <label for="public_key">Public Key</label><br>
                <input type="string" style="width: 100%;" id="public_key" name="public_key" value="" />
            </span>
            <input type="submit" value="Add Wireguard Key">
        </form>
        <div id="msg_box"></div>
        </div>


   </body>
</html>

<script>
var form = document.getElementById('key_form');
form.onsubmit = function(event){
        var xhr = new XMLHttpRequest();
        var formData = new FormData(form);
        //open the request
        xhr.open('POST','/api/add_key')
        xhr.setRequestHeader("Content-Type", "application/json");

        //send the form data
        xhr.send(JSON.stringify(Object.fromEntries(formData)));

        xhr.onreadystatechange = function() {
            if (xhr.readyState == XMLHttpRequest.DONE) {
                form.reset(); //reset form after AJAX success or do something else
                console.log(xhr.response)
                document.getElementById("msg_box").innerHTML = xhr.response;
            }
        }
        //Fail the onsubmit to avoid page refresh.
        return false;
    }
</script>
'''
# https://stackoverflow.com/a/69374442

if __name__ == "__main__":
    app.run()
