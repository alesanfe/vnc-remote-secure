import pathlib

for f in pathlib.Path('frontend/src').rglob('*.tsx'):
    t = f.read_text(encoding='utf-8')
    n = t.replace('className="error-box">',
                  'className="error-box" role="alert">')
    if n != t:
        f.write_text(n, encoding='utf-8')
        print('patched', f)
