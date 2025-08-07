from structlog.stdlib import get_logger
from vyper import v

LOGGER = get_logger(__name__)


def generate_config():
    url = (
        f"{v.get('database.username')}:"
        f"{v.get('database.password')}@"
        f"{v.get('database.host')}:{v.get('database.port')}/"
        f"{v.get('database.name')}"
    )
    v.set("database.url", f"postgresql+asyncpg://{url}")
    v.set("database.synchronous_url", f"postgresql+psycopg2://{url}")


def init_vyper():
    v.set_env_prefix("AIXCC")
    v.automatic_env()

    v.set_config_type("yaml")
    v.set_config_name("config")
    v.add_config_path("/etc/capi/")
    try:
        v.read_in_config()
    except FileNotFoundError:
        LOGGER.warning("Config file not found")

    generate_config()

    v.set_default("scoring.reject_duplicate_vds", True)
