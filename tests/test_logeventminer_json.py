import json

from logeventminer_json import analyze_json, format_json_path


def test_json_colors_distinguish_keys_values_and_literals():
    document = analyze_json('{\n  "key": "value",\n  "n": -1.2e+3,\n  "yes": true,\n  "none": null\n}\n')
    tokens = [(span.kind, document.text[span.start:span.end]) for span in document.spans]
    assert ("key", '"key"') in tokens
    assert ("string", '"value"') in tokens
    assert ("number", "-1.2e+3") in tokens
    assert ("literal", "true") in tokens
    assert ("literal", "null") in tokens
    assert ("punctuation", "{") in tokens


def test_paths_follow_nested_objects_arrays_and_empty_containers():
    document = analyze_json(json.dumps({"items": [{"name": "alpha"}, [], {}], "done": False}, indent=2))
    lines = document.text.splitlines()
    assert document.paths[lines.index('      "name": "alpha"')] == ("items", 0, "name")
    assert document.paths[lines.index("    [],")] == ("items", 1)
    assert document.paths[lines.index("    {}")] == ("items", 2)
    assert document.paths[lines.index("  ],")] == ("items",)
    assert document.paths[lines.index('  "done": false')] == ("done",)
    assert document.paths[-1] == ()


def test_escaped_keys_and_strings_do_not_confuse_the_path_stack():
    key = 'a"b\\c\n😀'
    document = analyze_json(json.dumps({key: ['} ], : "quotes"', 23]}, ensure_ascii=False, indent=2))
    assert document.paths[2] == (key, 0)
    assert document.paths[3] == (key, 1)
    assert format_json_path(("items", 12, "name")) == '$ › items › [12] › name'
    assert '\\n' in format_json_path((key,))
    assert "\n" not in format_json_path((key,))


def test_cropping_preserves_parent_path_and_clips_token_offsets():
    document = analyze_json(json.dumps({"items": [{"name": "alpha"}]}, indent=2) + "\n\n")
    start = document.text.index('"alpha"') + 2
    cropped = document.trim_start(start).with_prefix("[older output discarded]\n")
    assert cropped.paths[0] is None
    assert cropped.paths[1] == ("items", 0, "name")
    assert cropped.text[cropped.spans[0].start:cropped.spans[0].end] == 'lpha"'
    assert len(cropped.paths) == len(cropped.text.splitlines())
    assert all(0 <= span.start < span.end <= len(cropped.text) for span in cropped.spans)
    empty = document.trim_start(len(document.text))
    assert empty.text == "" and empty.paths == () and empty.spans == ()


def test_report_prefix_keeps_header_separate_from_json_paths():
    document = analyze_json('{"x": 1}\n\n').with_prefix("[time] cmdr_data\n", path=(), kind="header")
    assert document.paths == ((), (), ())
    assert document.spans[0].kind == "header"
    assert analyze_json(document.text, header_lines=1) == document
