import contextlib
import importlib
from types import SimpleNamespace


class EngineModule(SimpleNamespace):
    NAME: str
    LABEL: str
    DESCRIPTION: str
    SUPPORTS: str
    COST: str
    API_KEY_REQUIRED: str
    SUPPORTED_OBSERVABLE_TYPES: str


def load_engines(selected_engines: list[str]) -> list[EngineModule]:
    loaded_engines: list[EngineModule] = []

    """
    There's an inconsistency between the name listed in `gui_enabled_extensions`
    and the filename for `chrome_extension.py`
    """
    if "extension" in selected_engines:
        selected_engines = [engine for engine in selected_engines if engine != "extension"]
        selected_engines.append("chrome_extension")

    for engine in selected_engines:
        with contextlib.suppress(ModuleNotFoundError):
            loaded_engines.append(importlib.import_module(f"engines.{engine}"))  # type: ignore reportArgumentType

    return loaded_engines


def list_engines(selected_engines: list[str]) -> dict[str, dict[str, str]]:
    loaded_engines: list[EngineModule] = load_engines(selected_engines)
    return list_engine_metadata(loaded_engines)


def list_engine_metadata(loaded_engines: list[EngineModule]) -> dict[str, dict[str, str]]:
    """
    Return a list of engines and their descriptions, based on each engine's metadata attributes.
    """

    response: dict[str, dict[str, str]] = {}

    """Only return the engines that are enabled in the configuration."""
    for engine in loaded_engines:
        with contextlib.suppress(AttributeError):
            response.update(
                {
                    engine.NAME: {
                        "label": engine.LABEL,
                        "description": engine.DESCRIPTION,
                        "supports": engine.SUPPORTS,
                        "cost": engine.COST,
                        "api_key_required": engine.API_KEY_REQUIRED,
                        "supported_observable_types": engine.SUPPORTED_OBSERVABLE_TYPES,
                    }
                }
            )

    return response
