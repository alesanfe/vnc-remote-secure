import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(
    os.path.abspath(__file__)), "src"))
from vnc_remote_secure.cli import main
main()
