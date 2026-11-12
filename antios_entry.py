from antios.cli import main

if __name__ == "__main__":
    import sys
    from antios.scan_process import WORKER_FLAG, worker_main
    if len(sys.argv) == 4 and sys.argv[1] == WORKER_FLAG:
        raise SystemExit(worker_main(*sys.argv[2:]))
    raise SystemExit(main())
