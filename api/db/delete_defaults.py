"""
Utility script to delete entries from defaults table.

Usage:
  python -m api.db.delete_defaults --all              # Delete all entries
  python -m api.db.delete_defaults --female           # Delete only female
  python -m api.db.delete_defaults --male             # Delete only male
  python -m api.db.delete_defaults --other            # Delete only other
  python -m api.db.delete_defaults --ids 1 5 7        # Delete specific IDs
"""
import sys
import argparse
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from api.db.database import Database


def delete_by_gender(gender: str):
    """Delete all entries for a specific gender."""
    with Database() as db:
        db.cursor.execute("DELETE FROM defaults WHERE gender = %s", (gender,))
        count = db.cursor.rowcount
        print(f"Deleted {count} entries for gender '{gender}'")


def delete_all():
    """Delete all entries from defaults table."""
    with Database() as db:
        db.cursor.execute("DELETE FROM defaults")
        count = db.cursor.rowcount
        print(f"Deleted {count} entries (all)")


def delete_by_ids(ids: list):
    """Delete entries by specific IDs."""
    with Database() as db:
        db.cursor.execute("DELETE FROM defaults WHERE id = ANY(%s)", (ids,))
        count = db.cursor.rowcount
        print(f"Deleted {count} entries with IDs: {ids}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Delete entries from defaults table")
    parser.add_argument("--all", action="store_true", help="Delete all entries")
    parser.add_argument("--female", action="store_true", help="Delete only female clothing")
    parser.add_argument("--male", action="store_true", help="Delete only male clothing")
    parser.add_argument("--other", action="store_true", help="Delete only other clothing")
    parser.add_argument("--ids", nargs="+", type=int, help="Delete specific IDs (e.g., --ids 1 5 7)")
    args = parser.parse_args()

    # Check if any argument was provided
    if not any([args.all, args.female, args.male, args.other, args.ids]):
        parser.print_help()
        sys.exit(1)

    if args.all:
        delete_all()
    elif args.ids:
        delete_by_ids(args.ids)
    else:
        if args.female:
            delete_by_gender("female")
        if args.male:
            delete_by_gender("male")
        if args.other:
            delete_by_gender("other")

    print("Done!")
