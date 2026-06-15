import sys
from s7pwn.command_router import dispatch
from s7pwn.version import __version__

def main():
    args = sys.argv[1:]
    if not args:
        from s7pwn.cli import main as cli_main
        sys.exit(cli_main())

    # Xử lý global arguments (giống như --target)
    cmd_args = []
    i = 0
    target_ip = None
    rack = "0"
    slot = "1"
    while i < len(args):
        if args[i] == "--target" and i + 1 < len(args):
            target_ip = args[i+1]
            i += 2
        elif args[i] == "--rack" and i + 1 < len(args):
            rack = args[i+1]
            i += 2
        elif args[i] == "--slot" and i + 1 < len(args):
            slot = args[i+1]
            i += 2
        else:
            cmd_args.append(args[i])
            i += 1

    if target_ip:
        dispatch("set_target", [target_ip, rack, slot])

    if cmd_args:
        cmd = cmd_args[0].lower()
        dispatch(cmd, cmd_args[1:])

if __name__ == "__main__":
    main()
