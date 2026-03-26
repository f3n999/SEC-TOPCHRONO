"""
Configuration centralisee avec Pydantic Settings.
Charge les valeurs depuis .env ou variables d'environnement.
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from pathlib import Path


class AzureSettings(BaseSettings):
    client_id: str = Field(..., alias="AZURE_CLIENT_ID")
    client_secret: str = Field(..., alias="AZURE_CLIENT_SECRET")
    tenant_id: str = Field(..., alias="AZURE_TENANT_ID")

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class DatabaseSettings(BaseSettings):
    url: str = Field(default="sqlite+aiosqlite:///data/phishing_agent.db", alias="DATABASE_URL")
    echo: bool = Field(default=False, alias="DATABASE_ECHO")

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class ServerSettings(BaseSettings):
    host: str = Field(default="0.0.0.0", alias="API_HOST")
    port: int = Field(default=8080, alias="API_PORT")
    remote_server: str = Field(
        default="http://192.168.237.133:8000",
        alias="PHISHING_SERVER"
    )

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class ScanSettings(BaseSettings):
    default_emails_per_user: int = Field(default=25, alias="SCAN_DEFAULT_EMAILS")
    max_emails_per_user: int = Field(default=100, alias="SCAN_MAX_EMAILS")
    schedule_interval_minutes: int = Field(default=60, alias="SCAN_INTERVAL_MINUTES")
    rules_file: str = Field(default="config/rules.yaml", alias="RULES_FILE")

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class Settings(BaseSettings):
    azure: AzureSettings = AzureSettings
    database: DatabaseSettings = DatabaseSettings
    server: ServerSettings = ServerSettings
    scan: ScanSettings = ScanSettings
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    data_dir: str = Field(default="data", alias="DATA_DIR")

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.azure = AzureSettings()
        self.database = DatabaseSettings()
        self.server = ServerSettings()
        self.scan = ScanSettings()
        # Creer le dossier data si besoin
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    return Settings()
