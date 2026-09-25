import json, re, glob

schema = json.load(open(r'src/vnc_remote_secure/config/schema/config.schema.json', encoding='utf-8'))
props = set(schema.get('properties', {}))
print(len(props), 'schema props')

def_env = set()
for f in glob.glob(r'src/vnc_remote_secure/config/defaults/*.env'):
    for line in open(f, encoding='utf-8'):
        m = re.match(r'^([A-Z0-9_]+)=', line.strip())
        if m:
            def_env.add(m.group(1))
ex_env = set()
for f in glob.glob(r'src/vnc_remote_secure/config/examples/*') + glob.glob(r'.env*'):
    for line in open(f, encoding='utf-8', errors='replace'):
        m = re.match(r'^([A-Z0-9_]+)=', line.strip())
        if m:
            ex_env.add(m.group(1))

code_env = set()
for f in glob.glob(r'src/vnc_remote_secure/**/*.py', recursive=True):
    t = open(f, encoding='utf-8').read()
    code_env |= set(re.findall(r"""os\.environ\.get\(['"]([A-Z0-9_]+)['"]""", t))
    code_env |= set(re.findall(r"""env_flag\(['"]([A-Z0-9_]+)['"]""", t))
    code_env |= set(re.findall(r"""os\.getenv\(['"]([A-Z0-9_]+)['"]""", t))
    code_env |= set(re.findall(r"""os\.environ\[['"]([A-Z0-9_]+)['"]\]""", t))

SYSTEM = {'PATH','PYTHON','USER','USERNAME','USERPROFILE','LOCALAPPDATA',
          'XDG_RUNTIME_DIR','X','PROCESSOR_ARCHITECTURE','HOME','SHELL',
          'TEMP','TMP','SYSTEMROOT','WINDIR','COMSPEC','VIRTUAL_ENV',
          'SYSTEMDRIVE','PROGRAMFILES','APPDATA','LANG','LC_ALL','PWD'}
proj = code_env - SYSTEM
missing = proj - props - def_env - ex_env
print('=== project env vars read but NOT in schema/defaults/examples ===')
for v in sorted(missing):
    print(' ', v)
print('=== schema props never read in src (possible dead config) ===')
for v in sorted(props - code_env):
    print(' ', v)
print('=== defaults keys never read in src ===')
for v in sorted(def_env - code_env - props):
    print(' ', v)
