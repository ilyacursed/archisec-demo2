import json
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from services.analyzer import analyze_profile
from services.catalogs import list_catalog, catalog_item
from services.profile_validation import ProfileValidationError
from services.terminology import html_error
from services.result_presentation import (
    build_result_presentation, build_profile_form, default_profile_form,
)


def home(request):
    return render(request, "home.html")


def profile(request):
    return render(request, "profile.html", {"profile_form": default_profile_form()})


def _profile_from_post(request):
    return {
        "system_type": request.POST.get("system_type", "web"),
        "interfaces": request.POST.getlist("interfaces"),
        "internet_exposed": request.POST.get("internet_exposed") == "on",
        "data_classes": request.POST.getlist("data_classes"),
        "uses_ai": request.POST.get("uses_ai") == "on",
    }


@require_POST
def profile_analyze(request):
    try:
        result = analyze_profile(_profile_from_post(request))
    except ProfileValidationError as error:
        # Plain text avoids reflecting untrusted input into HTML; no error
        # template is required. Django CSRF protection remains enabled here.
        return HttpResponse(
            html_error(error.code, error.field),
            status=400,
            content_type="text/plain; charset=utf-8",
        )
    return render(request, "result.html", {
        "result": result,
        "presentation": build_result_presentation(result),
        "profile_form": build_profile_form(result["profile"]),
    })


def catalog(name):
    @require_GET
    def view(request):
        return JsonResponse(list_catalog(name))
    return view


def catalog_detail(name):
    @require_GET
    def view(request, code):
        result = catalog_item(name, code)
        if result is None:
            return JsonResponse({"error": "not_found"}, status=404)
        return JsonResponse(result)
    return view


@csrf_exempt  # TODO Phase 3: replace temporary demo API exemption with API CSRF strategy.
@require_POST
def api_profile_analyze(request):
    try:
        payload = json.loads(request.body)
    # Python may raise ValueError (rather than JSONDecodeError) for parser
    # safety limits such as an oversized integer, and RecursionError for
    # excessively nested input. Keep these expected boundary failures a
    # controlled client error; do not broaden the analyzer exception handler.
    except (ValueError, UnicodeDecodeError, RecursionError):
        return JsonResponse({"error": "invalid_json"}, status=400)
    try:
        result = analyze_profile(payload)
    except ProfileValidationError as error:
        return JsonResponse(error.as_dict(), status=400)
    return JsonResponse(result)
