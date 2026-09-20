import re

SITES = {
    'src/vnc_remote_secure/platform/linux/adapter.py': [42, 43, 47, 59, 72, 88],
    'src/vnc_remote_secure/platform/linux/installer.py': [108],
    'src/vnc_remote_secure/platform/linux/permissions.py': [36, 54, 74],
    'src/vnc_remote_secure/platform/linux/services.py': [26, 35, 36, 40],
    'src/vnc_remote_secure/platform/windows/adapter.py': [55],
    'src/vnc_remote_secure/platform/windows/services.py': [61, 68, 77, 90, 91],
    'src/vnc_remote_secure/security/certificates.py': [47, 286],
}

IMPORT = 'from vnc_remote_secure.core.processes import run_cmd'

for path, lines in SITES.items():
    src = open(path, encoding='utf-8').read()
    # Replace subprocess.run( occurrences at the given line numbers.
    out_lines = src.split('\n')
    for ln in lines:
        idx = ln - 1
        assert 'subprocess.run(' in out_lines[idx], f'{path}:{ln} mismatch: {out_lines[idx]!r}'
        out_lines[idx] = out_lines[idx].replace('subprocess.run(', 'run_cmd(')
    src = '\n'.join(out_lines)
    # Ensure the import exists (after the module docstring / existing imports).
    if IMPORT not in src:
        # insert after last top-level 'import ' or 'from ' line
        lines2 = src.split('\n')
        last_imp = max(i for i, l in enumerate(lines2)
                       if l.startswith(('import ', 'from ')))
        lines2.insert(last_imp + 1, IMPORT)
        src = '\n'.join(lines2)
    open(path, 'w', encoding='utf-8', newline='\n').write(src)
    print('migrated', path)
