import re, glob, os, yaml

root = r'C:\Users\alex0\PycharmProjects\vnc-remote-secure'

# 1. audit events emitted in code
emitted = {}
for f in glob.glob(root + r'\src\vnc_remote_secure\**\*.py', recursive=True):
    t = open(f, encoding='utf-8').read()
    for m in re.finditer(r"audit_event\(\s*['\"]([^'\"]+)['\"]", t):
        emitted.setdefault(m.group(1), []).append(
            f.replace(root + '\\', '').replace('/', '\\') + ':' +
            str(t[:m.start()].count('\n') + 1))

print('=== audit_event names in code ===')
for name in sorted(emitted):
    print(f'  {name}  x{len(emitted[name])}  {emitted[name][0]}')

# 2. documented events
doc = open(root + r'\docs\security\audit-events.md', encoding='utf-8').read()
documented = set(re.findall(r'`([a-z_]+)`', doc))
print('\n=== documented names ===')
print(sorted(documented))

print('\n=== emitted but NOT documented ===')
for n in sorted(set(emitted) - documented):
    print(f'  {n}  ({emitted[n][0]})')
print('\n=== documented but NEVER emitted ===')
for n in sorted(documented - set(emitted)):
    print(f'  {n}')

# 3. env vars read in code vs schema/defaults
code_env = set()
for f in glob.glob(root + r'\src\vnc_remote_secure\**\*.py', recursive=True):
    t = open(f, encoding='utf-8').read()
    for m in re.finditer(r"os\.environ\.get\(\s*['\"]([A-Z0-9_]+)['\"]", t):
        code_env.add(m.group(1))
    for m in re.finditer(r"env_flag\(\s*['\"]([A-Z0-9_]+)['\"]", t):
        code_env.add(m.group(1))
    for m in re.finditer(r"os\.getenv\(\s*['\"]([A-Z0-9_]+)['\"]", t):
        code_env.add(m.group(1))

schema_env = set()
for f in glob.glob(root + r'\config\schema\*.json') + glob.glob(root + r'\src\vnc_remote_secure\config\schema\*.json'):
    import json
    try:
        schema_env |= set(json.load(open(f, encoding='utf-8')).keys())
    except Exception:
        pass
def_env = set()
for f in glob.glob(root + r'\src\vnc_remote_secure\config\defaults\*.env'):
    for line in open(f, encoding='utf-8'):
        m = re.match(r'^([A-Z0-9_]+)=', line.strip())
        if m:
            def_env.add(m.group(1))
ex_env = set()
for f in glob.glob(root + r'\src\vnc_remote_secure\config\examples\*.env*') + glob.glob(root + r'\.env*'):
    for line in open(f, encoding='utf-8', errors='replace'):
        m = re.match(r'^([A-Z0-9_]+)=', line.strip())
        if m:
            ex_env.add(m.group(1))

print('\n=== env read in code but NOT in schema/defaults/examples ===')
for v in sorted(code_env - schema_env - def_env - ex_env):
    print(f'  {v}')
