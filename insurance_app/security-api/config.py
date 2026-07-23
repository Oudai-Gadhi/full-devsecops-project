import os

class Config:
    PGHOST = os.getenv("PGHOST")
    PGPORT = os.getenv("PGPORT", "5432")
    PGDATABASE = os.getenv("PGDATABASE")
    PGUSER = os.getenv("PGUSER")
    PGPASSWORD = os.getenv("PGPASSWORD")
