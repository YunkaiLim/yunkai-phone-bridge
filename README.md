# Yunkai Phone Bridge

A local-first Android MCP bridge for bounded device perception and interaction over ADB.

This repository is a sanitized public-source export of the PhoneBridge used in the Yunkai project. It keeps the important control boundaries: read-only inspection first, a narrow ADB action surface, semantic/reflex UI targeting, deterministic verification, local policy, and passive health/status surfaces.

## Highlights

- Android device discovery and bounded ADB connectivity
- screenshots and UI hierarchy inspection
- allowlisted key and app-launch actions
- semantic/reflex UI observation and guarded verified taps
- passive health and runtime status
- capability manifest, permission state, and unified device contract adapter
- optional localhost-only vision fallback
- companion-owned local integration surface
- source-only Control Center helper
- bounded Android 11+ wireless ADB recovery

## Deliberate non-capabilities

The public bridge is not an arbitrary remote shell. It does not expose generic shell execution, root, APK installation, delete, uninstall, or clear-data tools.

Verified actions follow `observe -> one action -> bounded re-observation -> report`; they are not silently replayed after ambiguous results.

## Public export boundary

This repository does **not** contain real tunnel IDs, runtime credentials, owner-specific configuration, caches, private verification captures, or tunnel-client/cloudflared binaries.

The shared contract modules required by the bridge are included under `yunkai_shared/`.

## Requirements

- Python 3.10+
- Android Platform Tools / `adb` installed locally
- an Android device you are authorized to control, with ADB debugging enabled and paired/authorized
- Python dependencies in `requirements.txt`

## Quick start

```powershell
git clone https://github.com/YunkaiLim/yunkai-phone-bridge.git
cd yunkai-phone-bridge
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
adb devices
cd PhoneBridge
python server_stdio.py
```

For the local HTTP entry point:

```powershell
cd PhoneBridge
python server.py
```

Optional local vision can be configured by copying `PhoneBridge/phonebridge_vision.example.json` to `phonebridge_vision.json`. Reflex policy has a separate checked-in example file.

## Tests

From `PhoneBridge/`:

```powershell
python -m unittest
```

During public-release preparation on 2026-09-30, the focused public suite passed **216 tests** across core ADB behavior, local vision, wireless reliability, Reflex, passive health, companion-owned integration, and Control Center logic.

Live ADB/device acceptance still depends on your own authorized device, OEM behavior, and local Android tooling.

## Security model

Read `SECURITY.md`. Keep ADB authorization under the device owner's control and do not broaden the bridge into arbitrary shell execution merely for convenience.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

Third-party components remain under their own licenses; see `THIRD_PARTY_NOTICES.md`.

This project is independent source code and is not an official OpenAI product.
