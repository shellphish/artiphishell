from pathlib import Path

from aijon_lib import CodeSwipePOI, PatchPOI


def test_nginx_codeswipe_report():
    """
    Test the CodeSwipe POI interface with a sample report.
    """
    report_path = Path(__file__).parent.parent / "tests_data" / "codeswipe_example.yaml"
    all_pois = list(CodeSwipePOI.parse_poi_from_codeswipe_report(report_path))
    assert len(all_pois) == 1070
    assert all_pois[0] == {
        "file_name": "ngx_cycle.c",
        "function_index_key": "/src/nginx/src/core/ngx_cycle.c:1656:1::ngx_int_t ngx_black_list_remove(ngx_black_list_t **, int *)",
        "metadata": {
            "diffguy_category": "overlap",
            "potentially_dangerous_code": ["for "],
        },
        "priority_score": 10.5,
    }


def test_libpng_diff_poi():
    raise NotImplementedError()
    report_path = Path(__file__).parent.parent / "tests_data" / "libpng.patch"


if __name__ == "__main__":
    test_nginx_codeswipe_report()
    print("Test passed!")
