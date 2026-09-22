"""Security test: verify file permissions are correct."""
import os


def test_env_example_not_secret():
    """The .env.example file should not contain real secrets."""
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    env_example = os.path.join(project_root, '.env.example')
    if os.path.exists(env_example):
        with open(env_example) as f:
            content = f.read()
        assert 'changeme' not in content.lower()
        assert 'YOUR_TOKEN' in content or 'your-token' in content or 'DUCKDNS_TOKEN=' in content


def test_env_example_no_real_passwords():
    """.env.example must use placeholders, never plausible secrets."""
    project_root = os.path.dirname(os.path.dirname(
        os.path.dirname(__file__)))
    env_example = os.path.join(project_root, '.env.example')
    if not os.path.exists(env_example):
        return
    with open(env_example, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, val = line.partition('=')
            if any(s in key for s in
                   ('PASSWORD', 'PASSWD', 'SECRET', 'TOKEN', 'KEY')):
                assert val == '' or 'your' in val.lower() or \
                    '<' in val or val.upper() == 'CHANGE_ME', \
                    f'{key} has a plausible real value: {val!r}'


def test_gitignore_covers_secrets():
    """.gitignore must cover .env, *.key, *.pem — a missing rule is a
    credential-leak waiting to happen."""
    project_root = os.path.dirname(os.path.dirname(
        os.path.dirname(__file__)))
    gi = os.path.join(project_root, '.gitignore')
    if not os.path.exists(gi):
        return
    content = open(gi, encoding='utf-8').read()
    for pat in ('.env', '.key', '.pem'):
        assert pat in content, f'.gitignore missing {pat}'
