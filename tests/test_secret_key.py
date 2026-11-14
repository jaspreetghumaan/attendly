"""Secret key: random when not configured, saved and reused, env var wins.

Runs on a temporary copy of the project, so the real .secret_key is never touched.
"""
import os, re, shutil, stat, subprocess, sys, tempfile

SRC = os.environ.get("ATTENDLY_PROJECT", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
work = tempfile.mkdtemp()
PROJECT = os.path.join(work, "proj")
shutil.copytree(SRC, PROJECT, ignore=shutil.ignore_patterns(".secret_key", "__pycache__", "*.db", "tests"))
KEYFILE = os.path.join(PROJECT, ".secret_key")
base_env = {k: v for k, v in os.environ.items() if k != "ATTENDLY_SECRET_KEY"}
PRINT_KEY = "import config; print(config.SECRET_KEY)"


def run_key(env):
    return subprocess.run([sys.executable, "-c", PRINT_KEY], cwd=PROJECT, env=env,
                          capture_output=True, text=True, check=True).stdout.strip()


def check(name, fn):
    try:
        fn(); print(f"PASS  {name}"); return True
    except AssertionError as e:
        print(f"FAIL  {name} -> {e}"); return False


def t_random_key_created_and_saved():
    key = run_key(base_env)
    assert os.path.exists(KEYFILE), "key file not created"
    assert open(KEYFILE).read().strip() == key
    assert re.fullmatch(r"[0-9a-f]{64}", key), key
    assert key != "dev-only-change-me"
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(KEYFILE).st_mode) == 0o600


def t_same_key_after_restart():
    first = open(KEYFILE).read().strip()
    assert run_key(base_env) == first


def t_env_var_overrides_and_no_file_written():
    os.remove(KEYFILE)
    assert run_key(dict(base_env, ATTENDLY_SECRET_KEY="my-prod-key")) == "my-prod-key"
    assert not os.path.exists(KEYFILE)


def t_simultaneous_starts_share_one_key():
    if os.path.exists(KEYFILE):
        os.remove(KEYFILE)
    procs = [subprocess.Popen([sys.executable, "-c", PRINT_KEY], cwd=PROJECT, env=base_env,
                              stdout=subprocess.PIPE, text=True) for _ in range(12)]
    keys = {p.communicate()[0].strip() for p in procs}
    assert len(keys) == 1, f"{len(keys)} different keys"
    assert keys == {open(KEYFILE).read().strip()}
    assert not [f for f in os.listdir(PROJECT) if f.startswith(".secret_key.")]


ok = all([
    check("random key created and saved (64 hex, mode 600)", t_random_key_created_and_saved),
    check("same key after restart", t_same_key_after_restart),
    check("ATTENDLY_SECRET_KEY overrides, no file written", t_env_var_overrides_and_no_file_written),
    check("12 simultaneous starts share one key", t_simultaneous_starts_share_one_key),
])
shutil.rmtree(work, ignore_errors=True)
sys.exit(0 if ok else 1)
