import psycopg2
from config import Config

def get_conn():
    return psycopg2.connect(
        host=Config.PGHOST,
        port=Config.PGPORT,
        dbname=Config.PGDATABASE,
        user=Config.PGUSER,
        password=Config.PGPASSWORD
    )
