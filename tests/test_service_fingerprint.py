from shadowstrike.engines.tcp import _banner_service


def test_banner_service_classification() -> None:
    assert _banner_service(22, "SSH-2.0-OpenSSH_9.8") == "ssh"
    assert _banner_service(25, "220 mx.example ESMTP Exim 4.98") == "smtp"
    assert _banner_service(21, "220 Pure-FTPd") == "ftp"
