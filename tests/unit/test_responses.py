import gzip

from main import HttpRequest, build_response


def make_request(path, *, method="GET", headers=None, body=b""):
    return HttpRequest(method, path, headers or {}, body)


def test_build_response_root_returns_empty_response(tmp_path):
    response = build_response(make_request("/"), str(tmp_path))
    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.body == b""


def test_build_response_echo_respects_gzip(tmp_path):
    headers = {"accept-encoding": "gzip"}
    response = build_response(make_request("/echo/sample", headers=headers), str(tmp_path))
    assert response.headers.get("Content-Encoding") == "gzip"
    assert gzip.decompress(response.body) == b"sample"


def test_file_get_streams_existing_file(tmp_path):
    file_path = tmp_path / "data.txt"
    file_path.write_bytes(b"payload")
    response = build_response(make_request(f"/files/{file_path.name}"), str(tmp_path))
    assert response.use_chunked
    assert response.body_iter is not None


def test_file_post_persists_payload(tmp_path):
    body = b"uploaded"
    response = build_response(
        make_request(f"/files/uploaded.txt", method="POST", body=body),
        str(tmp_path),
    )
    assert response.status_line == "HTTP/1.1 201 Created"
    stored = (tmp_path / "uploaded.txt").read_bytes()
    assert stored == body
