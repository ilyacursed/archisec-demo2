import json
from pathlib import Path
from django.test import SimpleTestCase
from django.urls import reverse
from services.mappings import validate_mappings


class SmokeTests(SimpleTestCase):
    def test_home(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "АрхиСек")

    def test_profile(self):
        self.assertEqual(self.client.get("/profile/").status_code, 200)
        self.assertEqual(self.client.get("/api/profile/analyze/").status_code, 405)

    def test_profile_html_analysis(self):
        response = self.client.post("/profile/analyze/", {"system_type":"web", "interfaces":["web"]})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "DEMO-T-001")

    def test_profile_api_analysis(self):
        response = self.client.post(
            "/api/profile/analyze/",
            data=json.dumps({"system_type":"web", "interfaces":["web"], "internet_exposed":True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["metadata"]["source"], "demo")
        self.assertGreaterEqual(payload["statistics"]["threats"], 1)

    def test_invalid_json(self):
        response = self.client.post("/api/profile/analyze/", data="{", content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_catalog(self):
        response = self.client.get("/api/threats/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["source"], "demo")

    def test_mappings(self):
        self.assertEqual(validate_mappings(), [])

    def test_all_demo_ids(self):
        data_dir = Path(__file__).resolve().parent.parent / "data"
        for path in data_dir.glob("*.json"):
            text = path.read_text(encoding="utf-8")
            if path.name != "mappings.json":
                self.assertNotIn('"ЗИС.', text)
                self.assertNotIn('"ИАФ.', text)
