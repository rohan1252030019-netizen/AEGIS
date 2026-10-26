import logging
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from app.config import settings

logger = logging.getLogger(__name__)

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")
_is_mysql = "mysql" in settings.DATABASE_URL

if _is_sqlite:
    # SQLite does not support pool_size / max_overflow / pool_recycle.
    from sqlalchemy.pool import StaticPool
    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=settings.AEGIS_ENV == "development",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
elif _is_mysql:
    # MySQL / aiomysql — pool_pre_ping keeps connections alive,
    # pool_recycle prevents "server has gone away" on idle connections.
    connect_args = {}
    if "tidbcloud" in settings.DATABASE_URL or "ssl" in settings.DATABASE_URL.lower():
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        connect_args["ssl"] = ctx
    engine = create_async_engine(
        settings.DATABASE_URL,
        connect_args=connect_args,
        echo=settings.AEGIS_ENV == "development",
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=False,
        pool_recycle=1800,
    )
else:
    # PostgreSQL (asyncpg)
    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=settings.AEGIS_ENV == "development",
        pool_size=20,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=300,
    )

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    """Run on startup to verify database connectivity and log configuration."""
    db_display = settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else settings.DATABASE_URL
    logger.info(f"Database URL: {db_display}")

    async with engine.begin() as conn:
        if _is_sqlite:
            result = await conn.exec_driver_sql("SELECT sqlite_version()")
            version = result.scalar()
            logger.info(f"SQLite version: {version}")
        elif _is_mysql:
            result = await conn.exec_driver_sql("SELECT VERSION()")
            version = result.scalar()
            logger.info(f"MySQL version: {version}")
        else:
            result = await conn.exec_driver_sql("SELECT version()")
            version = result.scalar()
            logger.info(f"PostgreSQL version: {version}")


async def get_db() -> AsyncSession:
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()
