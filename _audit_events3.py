import re, glob

for f in glob.glob(r'src/vnc_remote_secure/engine/**/*.py', recursive=True) + \
         glob.glob(r'src/vnc_remote_secure/cli/**/*.py', recursive=True):
    t = open(f, encoding='utf-8').read()
    for m in re.finditer(r"""(stores\.audit|audit|_audit_cli)\(\s*['"]([a-z_]+)['"]""", t):
        line = t[:m.start()].count('\n') + 1
        print(f + ':' + str(line), m.group(1), m.group(2))
