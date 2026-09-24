import threading
import uvicorn
from scanner.bola import scan_bola
from scanner.models import Identity

def test_bola_against_vulnerable_sandbox():
    config = uvicorn.Config("sandbox.app:app", host="127.0.0.1", port=8765, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    import time; time.sleep(0.5)
    finding = scan_bola("http://127.0.0.1:8765", "/orders/{id}", Identity("user-a","user-a-token"), "101", "102")
    server.should_exit = True
    thread.join(timeout=2)
    assert finding is not None
    assert finding.kind == "BOLA"
    assert finding.confidence >= 0.9
