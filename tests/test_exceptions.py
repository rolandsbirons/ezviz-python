from ezviz.exceptions import (
    AuthError,
    DeviceOffline,
    EzvizError,
    MfaRequired,
    RegionRedirect,
)


def test_hierarchy():
    for exc in (AuthError, DeviceOffline):
        assert issubclass(exc, EzvizError)
    assert issubclass(MfaRequired, AuthError)
    assert issubclass(RegionRedirect, AuthError)


def test_region_redirect_carries_region():
    err = RegionRedirect("try eu", region="eu")
    assert err.region == "eu"
    assert isinstance(err, EzvizError)
