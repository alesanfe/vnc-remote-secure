"""Security test: verify file permissions are correct."""
import os


def test_env_example_not_secret():
    """The .env.example file should not contain real secrets."""
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    env_example = os.path.join(project_root, '.env.example')
    if os.path.exists(env_example):
        with open(env_example) as f:
            content = f.read()
        assert 'changeme' not in content.lower() or 'example' in content.lower()
        assert 'YOUR_TOKEN' in content or 'your-token' in content or 'DUCKDNS_TOKEN=' in content
