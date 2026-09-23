import pathlib, glob
# find existing validate_config tests
for f in glob.glob("tests/unit/core/*config*") + glob.glob("tests/unit/**/*inspector*"):
    print(f)