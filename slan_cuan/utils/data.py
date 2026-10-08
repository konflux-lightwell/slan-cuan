"""JSON parsing helpers with configurable error handling."""

import json
import logging
from pathlib import Path
from typing import IO, Any

log = logging.getLogger(__name__)


def _resolve_source_read_text(source: Path | str | IO[str]) -> str:
    if isinstance(source, Path):
        return source.read_text()
    if isinstance(source, str):
        return source
    return source.read()


def safe_json_load(
    source: Path | str | IO[str],
    parse_err_msg: str = "JSON file is malformed.",
    expected_type: type = dict,
    type_err_msg: str = "JSON file is not of the expected type.",
    raise_on_err: bool = True,
    raise_type: type[Exception] = ValueError,
    **kwargs: Any,
) -> Any:
    """Parse JSON safely from a path, an open file, or raw JSON text.

    Args:
        source: A path to a JSON file, an open file object, or raw JSON text.
        parse_err_msg: The error message to raise if the JSON is malformed.
        expected_type: The expected type of the JSON data.
        type_err_msg: The error message to raise if the JSON data is not of the
            expected type.
        raise_on_err: Whether to raise an exception if an error occurs.
        raise_type: The type of exception to raise if an error occurs.
        **kwargs: Additional keyword arguments to pass to the exception
            constructor.

    Returns:
        The JSON data.

    """
    try:
        text = _resolve_source_read_text(source)
        data = json.loads(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        if raise_on_err:
            raise raise_type(parse_err_msg, **kwargs) from e
        else:
            err_msg = f"Ignoring error: {parse_err_msg}"
            log.debug(err_msg, exc_info=True)
            return None
    if not isinstance(data, expected_type):
        if raise_on_err:
            raise raise_type(type_err_msg, **kwargs) from None
        else:
            err_msg = f"Ignoring error: {type_err_msg}"
            log.debug(err_msg, exc_info=True)
            return None
    return data
