"""MobileSentry configuration constants."""

from typing import ClassVar

from pydantic import BaseModel


class Config(BaseModel):
    """Global configuration for MobileSentry."""

    PACKAGE_NAME: ClassVar[str] = "mobilesentry"
    VERSION: ClassVar[str] = "0.1.0"
    OUTPUT_DIR: ClassVar[str] = "./mobilesentry_output"
    DECOMPILE_DIR: ClassVar[str] = "./mobilesentry_output/decompiled"
