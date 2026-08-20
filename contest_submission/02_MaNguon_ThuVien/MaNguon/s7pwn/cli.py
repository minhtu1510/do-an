from __future__ import annotations
import sys
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory
from s7pwn.command_router import dispatch
from s7pwn.version import __version__

COMMANDS = [
    "scan", "list", "select", "set_target", "show_target",
    "probe_target", "flood", "monitor", "read", "write", "rwrite",
    "export", "webgui", "help", "exit", "quit",
]

def main() -> int:
    print(f"\033[1mS7Pwn\033[0m {__version__}")
    history = InMemoryHistory()
    completer = WordCompleter(COMMANDS, ignore_case=True)
    session = PromptSession(completer=completer, history=history, complete_while_typing=False)
    while True:
        try:
            line = session.prompt("s7pwn> ").strip()
            if not line:
                continue
            parts = line.split()
            cmd, args = parts[0].lower(), parts[1:]
            if cmd in ("exit","quit"):
                return 0
            if cmd == "help":
                from s7pwn.commands.help import print_help
                print_help(); continue
            dispatch(cmd, args)
        except KeyboardInterrupt:
            print()
            continue
        except EOFError:
            print()
            return 0
        except Exception as e:
            print(f"Error: {e}")
            continue

if __name__ == "__main__":
    sys.exit(main())
