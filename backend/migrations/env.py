from alembic import context

from protocol_lab.services.settings import Settings
from protocol_lab.storage.database import Base, make_engine

url = Settings.environment().database_url
if not url:
    raise RuntimeError("Set PROTOCOL_LAB_DATABASE_URL in the project .env or environment")
if context.is_offline_mode():
    context.configure(url=url, target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = make_engine(url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()
