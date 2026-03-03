import glob
import os
import pwd
import re
import subprocess
import unicodedata

from pathlib import Path

from flask import Flask, jsonify, request


REPO = "/etc/wireguard/peers-wg"

app = Flask(__name__)
# TODO(ruairi): Refactor load_config to return Dataclass.

WG_PUBKEY_PATTERN = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")

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

    s = subprocess.Popen([cmd], shell=True, env=env,
                         preexec_fn=demote(user_uid, user_gid), stdout=subprocess.PIPE)
    s.wait()

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
