from ezviz.cli import build_parser


def test_parser_has_cameras_command():
    parser = build_parser()
    ns = parser.parse_args(["cameras", "--region", "eu"])
    assert ns.command == "cameras"
    assert ns.region == "eu"


def test_parser_has_records_command():
    parser = build_parser()
    ns = parser.parse_args(["records", "--serial", "AA1", "--date", "2026-07-23"])
    assert ns.command == "records"
    assert ns.serial == "AA1"
    assert ns.date == "2026-07-23"


def test_parser_has_download_command():
    parser = build_parser()
    ns = parser.parse_args(
        ["download", "--serial", "AA1", "--seconds", "10", "--out", "c.h265"]
    )
    assert ns.command == "download"
    assert ns.serial == "AA1"
    assert ns.seconds == 10
    assert ns.out == "c.h265"
