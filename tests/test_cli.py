from ezviz.cli import build_parser


def test_parser_has_cameras_command():
    parser = build_parser()
    ns = parser.parse_args(["cameras", "--region", "eu"])
    assert ns.command == "cameras"
    assert ns.region == "eu"
