from .gp import router as GPRouter
from .health import router as HealthRouter
from .vds import router as VDSRouter

__all__ = ["GPRouter", "HealthRouter", "VDSRouter"]
