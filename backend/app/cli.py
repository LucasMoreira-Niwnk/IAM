from __future__ import annotations

import argparse
import json
import sys

from .config import settings
from .database import connect, init_db
from .sync import DirectorySyncService


def sync_ad() -> int:
    with connect(settings.database_path) as connection:
        init_db(connection)
        result = DirectorySyncService(settings, connection).sync_read_only()

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("sync-ad", help="Sincroniza usuários e grupos do AD para o cache local.")

    args = parser.parse_args()
    if args.command == "sync-ad":
        return sync_ad()

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
