import glob
import os
import re

broken = []
for md in glob.glob('docs/**/*.md', recursive=True) + ['README.md', 'AGENTS.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'ROADMAP.md']:
    if not os.path.isfile(md):
        continue
    src = open(md, encoding='utf-8').read()
    base = os.path.dirname(md)
    for m in re.finditer(r'\]\(([^)\s]+)\)', src):
        link = m.group(1)
        if link.startswith(('http://', 'https://', 'mailto:', '#')):
            continue
        target = os.path.normpath(os.path.join(base, link.split('#')[0]))
        if not os.path.exists(target):
            broken.append(f'{md}: {link}')
for b in broken:
    print('BROKEN', b)
print('total broken:', len(broken))
