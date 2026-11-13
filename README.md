# IG-OSINT v1.0

Public Instagram OSINT analyzer for **Kali Linux** and **Termux (Android)**.

IG-OSINT collects publicly available Instagram profile data, extracts EXIF/GPS metadata from images, and uses **Gemini 2.5 Flash** multimodal AI to estimate a subject's country, region, and background from visual and textual clues.

> **Legal use only.** Analyze public profiles only. Respect Instagram's Terms of Service and your local privacy laws. Do not use this tool for stalking, harassment, or unauthorized surveillance.

---

## Features

- Public profile scraping via `instaloader`
- Profile picture + recent post image download
- EXIF metadata extraction with `Pillow`, including GPS coordinates
- Gemini multimodal analysis:
  - OCR on signage, certificates, banners, documents
  - Flags, uniforms, emblems, currency, electrical outlets
  - Architecture, landmarks, vegetation, weather patterns
  - Languages, scripts, captions, hashtags, location tags
- Color-coded terminal report with `rich`
- Saves Markdown report + raw evidence JSON under `output/`
- Graceful handling of private profiles, rate limits, and network errors
- Persistent Gemini API key storage (`~/.ig_osint/config.json`, mode `600`)

---

## Project Structure
