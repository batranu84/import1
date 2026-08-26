from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SHADOWSTRIKE_", env_file=".env", extra="ignore")

    database_path: str = "shadowstrike.db"
    host: str = "127.0.0.1"
    port: int = 8765
    default_concurrency: int = 128
    max_concurrency: int = 1024
    default_timeout_seconds: float = 3.0
    user_agent: str = "ShadowStrike/0.26.0 Authorized-Security-Assessment"
    enforce_scope: bool = True


settings = Settings()
