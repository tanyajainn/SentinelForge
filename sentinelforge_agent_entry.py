from sentinelforge.__main__ import main
import sys

if __name__ == "__main__":
    sys.argv = [sys.argv[0], "agent"]
    main()
