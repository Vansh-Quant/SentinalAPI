from scanner.parser import normalize

def test_openapi_endpoint_discovery():
    spec = {"openapi":"3.0.0","paths":{"/orders/{id}":{"get":{"operationId":"getOrder","responses":{"200":{"description":"ok"}}}}}}
    endpoints = normalize(spec)
    assert len(endpoints) == 1
    assert endpoints[0].path == "/orders/{id}"
    assert endpoints[0].method == "GET"

def test_invalid_spec():
    try:
        normalize({})
        assert False
    except ValueError:
        assert True
