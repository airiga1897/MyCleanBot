from django.test import Client, override_settings


@override_settings(MAX_REQUEST_BYTES=8)
def test_request_size_limit_rejects_large_body(client: Client) -> None:
    response = client.post("/login/", data="123456789", content_type="text/plain")
    assert response.status_code == 413


def test_request_size_limit_rejects_invalid_header(client: Client) -> None:
    response = client.get("/livez", CONTENT_LENGTH="not-a-number")
    assert response.status_code == 400
