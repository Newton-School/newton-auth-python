from urllib.parse import urlencode, urlsplit


def append_query_params(url: str, params: dict[str, str]) -> str:
    return "{}?{}".format(url, urlencode(params))


def derive_issuer_from_base_url(base_url: str) -> str:
    parsed = urlsplit(base_url)
    return "{}://{}".format(parsed.scheme, parsed.netloc)
