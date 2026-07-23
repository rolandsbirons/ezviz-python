"""ezviz-python — clean async EZVIZ library."""
from .camera import Camera
from .client import EzvizClient
from .exceptions import AuthError, CryptoError, EzvizError, MfaRequired, RegionRedirect
from .models import DefenceMode, Device, PtzDirection, Region, Switch

__version__ = "0.1.0"
__all__ = [
    "EzvizClient", "Camera", "Device", "Region", "PtzDirection", "Switch", "DefenceMode",
    "EzvizError", "AuthError", "MfaRequired", "RegionRedirect", "CryptoError",
    "__version__",
]
