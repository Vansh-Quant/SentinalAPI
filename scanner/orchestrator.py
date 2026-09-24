from .parser import load_spec, normalize
from .models import Identity

class Scanner:
    def discover(self, spec_source: str):
        return normalize(load_spec(spec_source))

    def identity(self, name: str, token: str, role: str = "user"):
        return Identity(name=name, token=token, role=role)
