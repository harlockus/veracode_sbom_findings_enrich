from sbom_findings.coordinates import artifact_name, library_ref_from_purl, looks_like_library_ref


def test_jar_filename_becomes_the_artifact_name():
    assert artifact_name("commons-collections4-4.0.jar", "4.0") == "commons-collections4"
    assert artifact_name("plexus-archiver-1.0-alpha-3.jar", "1.0-alpha-3") == "plexus-archiver"
    assert artifact_name("spring-webmvc", "4.3.10.RELEASE") == "spring-webmvc"


def test_maven_and_npm_match_the_swagger_examples():
    assert library_ref_from_purl("pkg:maven/net.minidev/json-smart@1.3.1") == "maven:net.minidev:json-smart:1.3.1:"
    assert library_ref_from_purl("pkg:npm/win32@0.9.12") == "npm:win32::0.9.12:"
    assert looks_like_library_ref("npm:win32::0.9.12:")
    assert looks_like_library_ref("maven:net.minidev:json-smart:1.3.1:")


def test_scoped_npm_and_golang_and_pypi():
    assert library_ref_from_purl("pkg:npm/%40angular/core@12.0.0") == "npm:@angular/core::12.0.0:"
    assert (
        library_ref_from_purl("pkg:golang/github.com/gin-gonic/gin@v1.7.0")
        == "go:github.com/gin-gonic/gin::v1.7.0:"
    )
    assert library_ref_from_purl("pkg:pypi/django@3.2.0") == "pypi:django::3.2.0:"


def test_non_coordinates_are_rejected():
    assert not looks_like_library_ref("pkg:npm/win32@0.9.12")
    assert not looks_like_library_ref("11111111-1111-1111-1111-111111111111")
    assert library_ref_from_purl("pkg:generic/thing@1") is None
