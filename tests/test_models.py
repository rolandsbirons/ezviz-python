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
    # New M4.5 fields default sanely when their sibling pagelist blocks
    # (STATUS/CONNECTION) aren't supplied.
    assert dev.sub_category == ""
    assert dev.version == ""
    assert dev.wan_ip is None
    assert dev.encrypted is False
    assert dev.local_ip is None
    assert dev.channels == 1


def test_device_from_api_maps_sub_category_and_version_from_deviceinfos_item():
    # Reference: camera.py::status() -- self.fetch_key(["deviceInfos",
    # "deviceSubCategory"]) / ["deviceInfos", "version"] -- both live directly
    # on the deviceInfos item itself, same as name/status/deviceCategory.
    payload = {
        "deviceSerial": "AA1234567",
        "name": "Front",
        "status": 1,
        "deviceCategory": "IPC",
        "deviceSubCategory": "C6CN",
        "version": "5.3.0 build 200101",
    }
    dev = Device.from_api(payload)
    assert dev.sub_category == "C6CN"
    assert dev.version == "5.3.0 build 200101"


def test_device_from_api_maps_encrypted_from_status_block():
    # Reference: camera.py::status() -- bool(self.fetch_key(["STATUS",
    # "isEncrypt"])) -- STATUS is a sibling pagelist block keyed by serial,
    # not part of the deviceInfos item.
    payload = {"deviceSerial": "AA1234567", "name": "Front", "status": 1}
    dev = Device.from_api(payload, status={"isEncrypt": 1})
    assert dev.encrypted is True
    dev_off = Device.from_api(payload, status={"isEncrypt": 0})
    assert dev_off.encrypted is False


def test_device_from_api_maps_wan_ip_from_connection_block():
    # Reference: camera.py::status() -- wan_ip = conn.get("netIp") or
    # self.fetch_key(["CONNECTION", "netIp"]) -- CONNECTION is a sibling
    # pagelist block keyed by serial (same block DeviceEndpoint already
    # reads localIp/localCmdPort from).
    payload = {"deviceSerial": "AA1234567", "name": "Front", "status": 1}
    dev = Device.from_api(payload, connection={"netIp": "203.0.113.9"})
    assert dev.wan_ip == "203.0.113.9"


def test_device_from_api_maps_local_ip_from_connection_block():
    # Reference: camera.py::status() -- "local_ip": self._local_ip(), whose
    # fallback chain reads CONNECTION.localIp (self._device.get("CONNECTION")
    # .get("localIp")) -- the same CONNECTION[serial] block wan_ip reads
    # netIp from, and the same field DeviceEndpoint.from_connection already
    # reads for the local-SDK live path.
    payload = {"deviceSerial": "AA1234567", "name": "Front", "status": 1}
    dev = Device.from_api(payload, connection={"localIp": "192.168.1.50"})
    assert dev.local_ip == "192.168.1.50"


def test_device_from_api_maps_channels_from_deviceinfos_item():
    # Reference: camera.py::status() -- "supported_channels":
    # self.fetch_key(["deviceInfos", "channelNumber"]) -- on the deviceInfos
    # item itself, like sub_category/version.
    payload = {
        "deviceSerial": "AA1234567", "name": "Front", "status": 1, "channelNumber": 2,
    }
    dev = Device.from_api(payload)
    assert dev.channels == 2


def test_device_from_api_defaults_channels_to_1_when_absent_or_invalid():
    base = {"deviceSerial": "AA1234567", "name": "Front", "status": 1}
    assert Device.from_api(base).channels == 1
    assert Device.from_api({**base, "channelNumber": 0}).channels == 1
    assert Device.from_api({**base, "channelNumber": "not-a-number"}).channels == 1
