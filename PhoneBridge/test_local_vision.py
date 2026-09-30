from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image as PILImage

from local_vision import LocalVisionAdapter, LocalVisionConfig, LocalVisionError, local_vision_status


class LocalVisionTests(unittest.TestCase):
    def test_rejects_non_local_url(self):
        with self.assertRaises(LocalVisionError):
            LocalVisionConfig.from_mapping(
                {
                    "provider": "ollama",
                    "model": "test-vlm",
                    "base_url": "https://example.com",
                }
            )

    def test_loads_optional_json_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "phonebridge_vision.json").write_text(
                json.dumps(
                    {
                        "enabled": True,
                        "provider": "ollama",
                        "model": "test-vlm",
                        "base_url": "http://127.0.0.1:11434",
                    }
                ),
                encoding="utf-8",
            )
            config = LocalVisionConfig.load(root)
            self.assertIsNotNone(config)
            assert config is not None
            self.assertEqual(config.provider, "ollama")
            self.assertEqual(config.model, "test-vlm")

    def test_disabled_when_no_config_exists(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            status = local_vision_status(Path(temp_dir))
            self.assertFalse(status["enabled"])
            self.assertFalse(status["configured"])

    def test_ollama_payload_and_json_result(self):
        calls = []

        def fake_transport(url, payload, timeout):
            calls.append((url, payload, timeout))
            return {
                "message": {
                    "content": json.dumps(
                        {
                            "summary": "Game screen with a continue button",
                            "screen_type": "game",
                            "texts": ["Continue"],
                            "targets": [
                                {
                                    "label": "Continue",
                                    "x": 800,
                                    "y": 500,
                                    "confidence": 0.95,
                                    "kind": "button",
                                }
                            ],
                            "warnings": [],
                        }
                    )
                }
            }

        config = LocalVisionConfig.from_mapping(
            {
                "provider": "ollama",
                "model": "test-vlm",
                "base_url": "http://127.0.0.1:11434",
            }
        )
        result = LocalVisionAdapter(config, transport=fake_transport).analyze_png(
            b"fake-png",
            width=1600,
            height=900,
        )
        self.assertTrue(result["parse_ok"])
        self.assertEqual(result["targets"][0]["x"], 800)
        self.assertEqual(calls[0][0], "http://127.0.0.1:11434/api/chat")
        self.assertEqual(calls[0][1]["model"], "test-vlm")
        self.assertTrue(calls[0][1]["messages"][0]["images"])
        self.assertEqual(calls[0][1]["options"]["num_ctx"], 4096)
        self.assertEqual(calls[0][1]["options"]["num_predict"], 512)
        self.assertEqual(calls[0][1]["format"]["properties"]["targets"]["maxItems"], 8)

    def test_downscale_maps_target_back_to_original_coordinates(self):
        calls = []

        def fake_transport(url, payload, timeout):
            calls.append((url, payload, timeout))
            return {
                "message": {
                    "content": json.dumps(
                        {
                            "summary": "center button",
                            "screen_type": "app",
                            "texts": [],
                            "targets": [
                                {
                                    "label": "center",
                                    "x": 400,
                                    "y": 200,
                                    "confidence": 1.0,
                                    "kind": "button",
                                }
                            ],
                            "warnings": [],
                        }
                    )
                }
            }

        buffer = io.BytesIO()
        PILImage.new("RGB", (1600, 800), "black").save(buffer, format="PNG")
        config = LocalVisionConfig.from_mapping(
            {
                "provider": "ollama",
                "model": "test-vlm",
                "base_url": "http://127.0.0.1:11434",
                "max_image_edge": 800,
            }
        )
        result = LocalVisionAdapter(config, transport=fake_transport).analyze_png(
            buffer.getvalue(),
            width=1600,
            height=800,
        )
        self.assertEqual(result["vision_input_size"], [800, 400])
        self.assertEqual(result["coordinate_space"], [1600, 800])
        self.assertEqual(result["targets"][0]["x"], 800)
        self.assertEqual(result["targets"][0]["y"], 400)
        self.assertIn("800x400", calls[0][1]["messages"][0]["content"])

    def test_lmstudio_payload(self):
        calls = []

        def fake_transport(url, payload, timeout):
            calls.append((url, payload, timeout))
            return {
                "choices": [
                    {
                        "message": {
                            "content": '{"summary":"Settings","screen_type":"app","texts":[],"targets":[],"warnings":[]}'
                        }
                    }
                ]
            }

        config = LocalVisionConfig.from_mapping(
            {
                "provider": "lmstudio",
                "model": "test-vlm",
                "base_url": "http://localhost:1234",
            }
        )
        result = LocalVisionAdapter(config, transport=fake_transport).analyze_png(
            b"fake-png",
            width=1080,
            height=2400,
        )
        self.assertTrue(result["parse_ok"])
        self.assertEqual(calls[0][0], "http://localhost:1234/v1/chat/completions")
        self.assertEqual(calls[0][1]["max_tokens"], 512)
        content = calls[0][1]["messages"][0]["content"]
        self.assertEqual(content[1]["type"], "image_url")
        self.assertTrue(content[1]["image_url"]["url"].startswith("data:image/png;base64,"))

    def test_actionable_targets_require_ui_kind_and_confidence(self):
        def fake_transport(url, payload, timeout):
            return {
                "message": {
                    "content": json.dumps(
                        {
                            "summary": "game",
                            "screen_type": "game",
                            "texts": [],
                            "targets": [
                                {"label": "NPC", "x": 10, "y": 10, "confidence": 0.99, "kind": "character"},
                                {"label": "Quest text", "x": 20, "y": 20, "confidence": 0.99, "kind": "text"},
                                {"label": "Weak button", "x": 30, "y": 30, "confidence": 0.7, "kind": "button"},
                                {"label": "dialogue button", "x": 35, "y": 35, "confidence": 0.99, "kind": "button"},
                                {"label": "Interact", "x": 40, "y": 40, "confidence": 0.91, "kind": "interact"},
                            ],
                            "warnings": [],
                        }
                    )
                }
            }

        config = LocalVisionConfig.from_mapping(
            {"provider": "ollama", "model": "test", "base_url": "http://127.0.0.1:11434"}
        )
        result = LocalVisionAdapter(config, transport=fake_transport).analyze_png(
            b"fake-png",
            width=100,
            height=100,
        )
        self.assertEqual([item["label"] for item in result["candidate_targets"]], ["dialogue button", "Interact"])
        self.assertEqual([item["label"] for item in result["actionable_targets"]], ["Interact"])
        self.assertTrue(result["actionable_targets"][0]["requires_verification"])
        self.assertEqual(result["min_action_confidence"], 0.85)

    def test_filters_out_of_bounds_targets(self):
        def fake_transport(url, payload, timeout):
            return {
                "message": {
                    "content": json.dumps(
                        {
                            "summary": "test",
                            "screen_type": "app",
                            "texts": [],
                            "targets": [
                                {"label": "bad", "x": 5000, "y": 1, "confidence": 1, "kind": "button"},
                                {"label": "good", "x": 10, "y": 20, "confidence": 2, "kind": "button"},
                            ],
                            "warnings": [],
                        }
                    )
                }
            }

        config = LocalVisionConfig.from_mapping(
            {"provider": "ollama", "model": "test", "base_url": "http://127.0.0.1:11434"}
        )
        result = LocalVisionAdapter(config, transport=fake_transport).analyze_png(
            b"fake-png",
            width=100,
            height=100,
        )
        self.assertEqual(len(result["targets"]), 1)
        self.assertEqual(result["targets"][0]["label"], "good")
        self.assertEqual(result["targets"][0]["confidence"], 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
