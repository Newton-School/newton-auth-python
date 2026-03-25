from urllib.parse import urlencode


def append_query_params(url: str, params: dict[str, str]) -> str:
    return "{}?{}".format(url, urlencode(params))
