from ezviz.models import Device, Region


def test_region_domain():
    assert Region.EU.api_domain == "apiieu.ezvizlife.com"
    assert Region.from_str("eu") is Region.EU


def test_device_from_api_maps_fields():
    payload = {
        "deviceSerial": "AA1234567",
        "name": "Front",
        "status": 1,  # 1 = online
        "deviceCategory": "IPC",
    }
    dev = Device.from_api(payload)
    assert dev.serial == "AA1234567"
    assert dev.name == "Front"
    assert dev.online is True
    assert dev.category == "IPC"
