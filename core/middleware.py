from __future__ import annotations

from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse


class RequestSizeLimitMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        raw_length = request.META.get("CONTENT_LENGTH")
        if raw_length:
            try:
                too_large = int(raw_length) > settings.MAX_REQUEST_BYTES
            except ValueError:
                return HttpResponse("Invalid Content-Length.", status=400)
            if too_large:
                return HttpResponse("Request is too large.", status=413)
        return self.get_response(request)
