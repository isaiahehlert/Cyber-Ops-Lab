import importlib
import pkgutil
"""
Orchestrator: discovers & runs handle_event() in sentinel.modules & zero.modules
"""

MODULE_PATHS = ["sentinel.modules", "zero.modules"]

def discover_and_run(event, **ctx):
    for pkg in MODULE_PATHS:
        path = pkg.replace('.', '/')
        for _, name, _ in pkgutil.iter_modules([path]):
            mod = importlib.import_module(f"{pkg}.{name}")
            if hasattr(mod, "handle_event"):
                mod.handle_event(event, **ctx)

if __name__ == "__main__":
    # example usage:
    discover_and_run("health_check")
    discover_and_run("quarantine", mac="AA-BB-CC-DD-EE-FF")
    discover_and_run("pentest", ip="192.168.1.100")
