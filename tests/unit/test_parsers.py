"""Tests for file parsers."""

from aisec.utils.parsers import parse_dockerfile, parse_package_json, parse_requirements_txt


def test_parse_dockerfile_basic():
    content = """\
FROM python:3.12-slim
EXPOSE 8080
ENV APP_ENV=production
RUN pip install aisec
USER nobody
ENTRYPOINT ["aisec"]
CMD ["scan"]
COPY . /app
"""
    info = parse_dockerfile(content)
    assert info.base_image == "python"
    assert info.base_tag == "3.12-slim"
    assert 8080 in info.exposed_ports
    assert info.env_vars.get("APP_ENV") == "production"
    assert "pip install aisec" in info.run_commands
    assert info.user == "nobody"
    assert info.entrypoint == '["aisec"]'
    assert info.cmd == '["scan"]'
    assert "." in info.copy_sources


def test_parse_dockerfile_no_tag():
    content = "FROM ubuntu\n"
    info = parse_dockerfile(content)
    assert info.base_image == "ubuntu"
    assert info.base_tag == "latest"


def test_parse_dockerfile_multiple_ports():
    content = "FROM node:18\nEXPOSE 3000 8080 9090/tcp\n"
    info = parse_dockerfile(content)
    assert sorted(info.exposed_ports) == [3000, 8080, 9090]


def test_parse_dockerfile_comments_and_empty():
    content = "# Comment\n\nFROM alpine:3.19\n# Another comment\nRUN echo hello\n"
    info = parse_dockerfile(content)
    assert info.base_image == "alpine"
    assert len(info.run_commands) == 1


def test_parse_requirements_txt():
    content = """\
# Dependencies
flask==2.3.0
requests>=2.28
numpy
pandas~=2.0
-r base.txt
"""
    deps = parse_requirements_txt(content)
    assert len(deps) == 4
    flask = next(d for d in deps if d.name == "flask")
    assert flask.pinned is True
    assert flask.version == "2.3.0"
    requests_dep = next(d for d in deps if d.name == "requests")
    assert requests_dep.pinned is False
    numpy = next(d for d in deps if d.name == "numpy")
    assert numpy.pinned is False
    assert numpy.version == ""


def test_parse_requirements_txt_empty():
    deps = parse_requirements_txt("")
    assert deps == []


def test_parse_package_json():
    content = """{
  "name": "my-app",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "4.17.21"
  },
  "devDependencies": {
    "jest": "~29.0.0"
  }
}"""
    deps = parse_package_json(content)
    assert len(deps) == 3
    express = next(d for d in deps if d.name == "express")
    assert express.pinned is False
    lodash = next(d for d in deps if d.name == "lodash")
    assert lodash.pinned is True


def test_parse_package_json_invalid():
    deps = parse_package_json("not json")
    assert deps == []


def test_parse_package_json_no_deps():
    deps = parse_package_json('{"name": "empty"}')
    assert deps == []
