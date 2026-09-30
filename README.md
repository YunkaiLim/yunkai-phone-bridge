# Yunkai Phone Bridge

A local-first Android MCP bridge for bounded device perception and interaction over ADB.

This repository is a sanitized public-source export of the PhoneBridge used in the Yunkai project. It keeps the important control boundaries: read-only inspection first, a narrow ADB action surface, semantic/reflex UI targeting, deterministic verification, local policy, and passive health/status surfaces.

## Highlights

- Android device discovery and bounded ADB connectivity
- screenshots and UI hierarchy inspection
- allowlisted key and app/URI actions
- semantic/reflex UI observation and guarded verified taps
- passive health and runtime status
- capability manifest, permission state, and unified device contract adapter
- optional localhost-only vision fallback
- companion-owned local integration surface
- source-only Control Center helper

## Deliberate non-capabilities

The public bridge is not an arbitrary remote shell. Keep ADB authorization under the device owner's control and preserve the existing action, identity, policy, and verification gates.

## Public export boundary

This repository does **not** contain real tunnel IDs, runtime credentials, owner-specific configuration, caches, local verification captures, or tunnel-client binaries. The private secure-tunnel launchers and bundled cloudflared executables are intentionally omitted from this first public source release.

The shared contract modules required by the bridge are included under `yunkai_shared/`.

## Requirements

- Python 3.11+
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

For the local HTTP entry point used by the original bridge:

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

The private working tree passed 217 unit tests immediately before this public export. Live ADB/device acceptance still depends on the user's own authorized device and local Android tooling.

## Security model

Read `SECURITY.md`. Do not broaden this bridge into arbitrary shell execution merely for convenience; the narrow surface is intentional.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

This project is independent source code and is not an official OpenAI product.
