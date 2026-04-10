import os
from sqlalchemy import create_engine


def _build_database_url() -> str:
    host = os.getenv("DB_HOST", "localhost")
    port = os.getenv("DB_PORT", "3306")
    user = os.getenv("DB_USER", "root")
    password = os.getenv("DB_PASSWORD", "")
    db_name = os.getenv("DB_NAME", "myapp_db")

    # mysql+pymysql supports empty passwords; include ':' only when provided.
    auth = f"{user}:{password}" if password else user
    return f"mysql+pymysql://{auth}@{host}:{port}/{db_name}?charset=utf8mb4"


engine = create_engine(
    _build_database_url(),
    pool_pre_ping=True,
)
