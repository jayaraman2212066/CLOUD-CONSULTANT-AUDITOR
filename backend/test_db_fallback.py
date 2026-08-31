import os
import sys

os.environ["DATABASE_URL"] = (
    "postgresql://postgres.invalid:pass@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres?sslmode=require"
)

sys.path.insert(0, os.path.dirname(__file__))

import sqlalchemy
import database


def main():
    db = database.SessionLocal()
    try:
        value = db.execute(sqlalchemy.text("SELECT 1")).scalar()
        assert value == 1, f"unexpected value: {value!r}"
        assert "sqlite" in str(database.engine.url), database.engine.url
    finally:
        db.close()

    print("DB fallback OK")


if __name__ == "__main__":
    main()
