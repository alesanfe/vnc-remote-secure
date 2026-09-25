import re, glob

root = r'src/vnc_remote_secure'
names = set()
for f in glob.glob(root + r'/**/*.py', recursive=True):
    t = open(f, encoding='utf-8').read()
    for pat in (r"""_audit\(\s*['"]([^'"]+)['"]""",
                r"""audit_event\(\s*['"]([^'"]+)['"]""",
                r"""stores\.audit\(\s*['"]([^'"]+)['"]""",
                r"""emit_audit\(\s*['"]([^'"]+)['"]""",
                r"""audit\(\s*['"]([a-z_]+)['"]"""):
        for m in re.finditer(pat, t):
            line = t[:m.start()].count('\n') + 1
            names.add(m.group(1))
            print(f.replace(root + '\\', '') + ':' + str(line), m.group(1))

print('\nALL:', sorted(names))
