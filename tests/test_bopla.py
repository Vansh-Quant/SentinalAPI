from scanner.bopla import analyze_response

def test_sensitive_property_detection():
    finding = analyze_response("/users/1", {"status_code":200,"body":{"id":"1","name":"Alice","password_hash":"x"}}, {"id","name"})
    assert finding is not None
    assert finding.kind == "BOPLA"

def test_public_fields_not_flagged():
    finding = analyze_response("/users/1", {"status_code":200,"body":{"id":"1","name":"Alice"}}, {"id","name"})
    assert finding is None
