import re, yaml, collections

root = r'C:\Users\alex0\PycharmProjects\vnc-remote-secure'

api_src = open(root + r'\src\vnc_remote_secure\services\api_v1.py', encoding='utf-8').read()
routes = sorted(set(re.findall(r"\('(GET|POST|PATCH|DELETE)',\s*'([^']+)'\)\s*:\s*_Route", api_src)))
print('=== api_v1 _ROUTES ===')
for m, p in routes:
    print(f'  {m} /api/v1/{p}')

# openapi paths
spec = yaml.safe_load(open(root + r'\docs\api\openapi.v1.yaml', encoding='utf-8'))
spec_routes = set()
for path, item in spec.get('paths', {}).items():
    for m in ('get', 'post', 'patch', 'delete', 'put'):
        if m in item:
            spec_routes.add((m.upper(), path.replace('{', '{').split('/')[-1] if False else path))
print('\n=== openapi paths ===')
for m, p in sorted(spec_routes):
    print(f'  {m} {p}')

# normalize: spec paths like /operators/{username} -> api route 'operators/{username}'
def norm(p):
    return re.sub(r'\{[^}]+\}', '{x}', p)

api_set = {(m, '/api/v1/' + norm(p)) for m, p in routes}
spec_set = {(m, p if p.startswith('/api') else '/api/v1' + p) for m, p in spec_routes}
spec_set = {(m, norm(p)) for m, p in spec_set}

print('\n=== in _ROUTES but NOT in openapi ===')
for m, p in sorted(api_set - spec_set):
    print(f'  {m} {p}')
print('\n=== in openapi but NOT in _ROUTES ===')
for m, p in sorted(spec_set - api_set):
    print(f'  {m} {p}')

# _Route signature: _Route(fn, perm, ratelimit, schema?, response?)
# find perms used
perms = re.findall(r"_Route\(\s*(\w+),\s*(None|'[^']+')", api_src)
print('\n=== perms in _Route entries ===')
for fn, perm in perms:
    pass
route_details = re.findall(r"\('(GET|POST|PATCH|DELETE)',\s*'([^']+)'\)\s*:\s*_Route\(\s*(\w+),\s*(None|'[^']*')", api_src)
perm_set = collections.Counter()
for m, p, fn, perm in route_details:
    perm_set[perm] += 1
print('\n'.join(f'  {k}: {v}' for k, v in perm_set.items()))

# frontend api calls
import os, glob
fe_calls = set()
for f in glob.glob(root + r'\frontend\src\**\*.ts*', recursive=True):
    t = open(f, encoding='utf-8').read()
    for m in re.findall(r"api\.(get|post|patch|delete)\s*<?[^>(]*>?\(\s*'([^']+)'", t):
        fe_calls.add((m[0].upper(), m[1]))
    for m in re.findall(r"api\.(get|post|patch|delete)\s*<?[^>(]*>?\(\s*`([^`]+)`", t):
        fe_calls.add((m[0].upper(), m[1]))
# api.ts helpers
api_ts = open(root + r'\frontend\src\api.ts', encoding='utf-8').read()
for m in re.findall(r"request<?[^>(]*>?\('([^']+)'", api_ts):
    fe_calls.add(('?', m))
print('\n=== frontend api paths ===')
for m, p in sorted(fe_calls):
    print(f'  {m} {p}')

api_path_set = {norm(p) for _, p in routes}
print('\n=== frontend calls NOT in _ROUTES ===')
for m, p in sorted(fe_calls):
    pn = norm(re.sub(r'\$\{[^}]+\}', '{x}', p))
    if pn not in api_path_set:
        print(f'  {m} {p}')

# perm strings vs ROLE_PERMISSIONS
ou = open(root + r'\src\vnc_remote_secure\security\operator_users.py', encoding='utf-8').read()
role_perms = set(re.findall(r"'([\w:*-]+)'", re.search(r'ROLE_PERMISSIONS\s*=\s*\{(.*?)\n\}', ou, re.S).group(1)))
all_perms = set(re.findall(r"'([\w:*-]+)'", re.search(r'ALL_PERMISSIONS\s*=\s*[\[\{\(](.*?)[\]\}\)]', ou, re.S).group(1))) if 'ALL_PERMISSIONS' in ou else set()
print('\n=== ROLE_PERMISSIONS ===', sorted(role_perms))
perm_names = {p.strip("'") for _, _, _, p in route_details if p != 'None'}
print('=== perms used in routes but NOT in ROLE_PERMISSIONS values ===')
print(sorted(perm_names - role_perms))
print('=== perms defined but never used in routes ===')
print(sorted(role_perms - perm_names - {'admin:*'}))
