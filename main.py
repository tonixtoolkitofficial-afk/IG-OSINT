#!/usr/bin/env python3
"""
IG-OSINT v1.2
Public Instagram profile OSINT analyzer with interactive proxy setup.

Features:
  - Public profile scraping via Instaloader
  - Image download + EXIF/GPS extraction via Pillow
  - Multimodal analysis via Google Gemini 2.5 Flash
  - Interactive proxy IP prompt + all traffic routed through proxy (IP masking)
  - Terminal report + saved Markdown/JSON evidence

Cross-platform: Kali Linux, Termux (Android), generic Linux.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import instaloader
import requests
from instaloader import Profile
from instaloader.exceptions import InstaloaderException
from PIL import Image, ExifTags
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from google import genai
from google.genai import types

from rich import box
from rich.align import Align
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

# ---------------------------------------------------------------------------
# Constants / paths
# ---------------------------------------------------------------------------

TOOL_NAME = "IG-OSINT"
VERSION = "1.2"
CONFIG_DIR = Path.home() / ".ig_osint"
CONFIG_FILE = CONFIG_DIR / "config.json"
OUTPUT_DIR = Path("output")
GEMINI_MODEL = "gemini-2.5-flash"

# Default Tor proxy (Termux/Kali both use 9050)
DEFAULT_TOR_PROXY = "socks5://127.0.0.1:9050"

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

BANNER = r"""
 ██╗ ██████╗       ██████╗ ███████╗██╗███╗   ██╗████████╗
 ██║██╔════╝      ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
 ██║██║  ███╗     ██║   ██║███████╗██║██╔██╗ ██║   ██║
 ██║██║   ██║     ██║   ██║╚════██║██║██║╚██╗██║   ██║
 ██║╚██████╔╝     ╚██████╔╝███████║██║██║ ╚████║   ██║
 ╚═╝ ╚═════╝       ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
"""

console = Console()

# ---------------------------------------------------------------------------
# Proxy helpers
# ---------------------------------------------------------------------------


def normalize_proxy(proxy_url: str) -> str:
    """Normalize proxy URL; auto-add scheme if missing."""
    proxy_url = proxy_url.strip()
    if not proxy_url:
        return ""
    if not proxy_url.startswith(("http://", "https://", "socks5://", "socks4://")):
        proxy_url = f"http://{proxy_url}"
    return proxy_url


def apply_proxy_env(proxy_url: str) -> None:
    """Set proxy for all child requests (Instaloader + requests)."""
    if not proxy_url:
        return
    os.environ["HTTP_PROXY"] = proxy_url
    os.environ["HTTPS_PROXY"] = proxy_url
    os.environ["http_proxy"] = proxy_url
    os.environ["https_proxy"] = proxy_url


def apply_proxy_to_loader(loader: instaloader.Instaloader, proxy_url: str) -> None:
    """Force Instaloader context session to use proxy."""
    if not proxy_url:
        return
    loader.context._session.proxies = {"http": proxy_url, "https": proxy_url}


def verify_proxy(proxy_url: str) -> Optional[str]:
    """
    Verify proxy connectivity by hitting an IP echo service.
    Returns the proxy exit IP, or None on failure.
    """
    try:
        proxies = {"http": proxy_url, "https": proxy_url}
        response = requests.get(
            "https://api.ipify.org?format=json",
            proxies=proxies,
            timeout=20,
        )
        response.raise_for_status()
        return response.json().get("ip")
    except Exception:
        return None


def prompt_proxy() -> str:
    """
    Ask the user for a proxy IP/URL. Default to Tor if user presses Enter.
    """
    console.print(
        Panel(
            "[bold cyan]Proxy Configuration[/bold cyan]\n\n"
            f"Press [bold]Enter[/bold] to use Tor ([cyan]{DEFAULT_TOR_PROXY}[/cyan])\n"
            "Or type a custom proxy URL:\n"
            "  • [dim]socks5://127.0.0.1:9050[/dim]        (Tor)\n"
            "  • [dim]http://user:pass@1.2.3.4:8080[/dim]  (HTTP proxy)\n"
            "  • [dim]socks5://1.2.3.4:1080[/dim]          (SOCKS5)\n"
            "  • [dim]none[/dim]                            (disable proxy)",
            title="🌐 Proxy Setup",
            border_style="cyan",
        )
    )

    raw = Prompt.ask("Enter proxy IP/URL", default=DEFAULT_TOR_PROXY).strip()

    if raw.lower() in ("none", "off", "no"):
        console.print("[yellow]Proxy disabled. Traffic will use your real IP.[/yellow]")
        return ""

    proxy_url = normalize_proxy(raw)
    console.print(f"[dim]Testing proxy connectivity...[/dim]")

    exit_ip = verify_proxy(proxy_url)
    if exit_ip:
        console.print(
            f"[green]✓ Proxy working. Exit IP:[/green] [cyan]{exit_ip}[/cyan]"
        )
    else:
        console.print(
            "[yellow]⚠ Could not verify proxy. Continuing anyway — "
            "check that Tor or your proxy is running.[/yellow]"
        )

    return proxy_url


# ---------------------------------------------------------------------------
# API key / config helpers
# ---------------------------------------------------------------------------


def load_saved_api_key() -> Optional[str]:
    try:
        if CONFIG_FILE.exists():
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            key = data.get("gemini_api_key")
            if isinstance(key, str) and key.strip():
                return key.strip()
    except Exception:
        pass
    return None


def save_api_key(api_key: str) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(
            json.dumps({"gemini_api_key": api_key.strip()}, indent=2),
            encoding="utf-8",
        )
        try:
            CONFIG_FILE.chmod(0o600)
        except Exception:
            pass
    except Exception as exc:
        console.print(f"[yellow]Could not save API key: {exc}[/yellow]")


def mask_key(key: str) -> str:
    if len(key) <= 8:
        return "****"
    return f"{key[:4]}{'*' * (len(key) - 8)}{key[-4:]}"


def resolve_api_key(reset: bool = False) -> Optional[str]:
    if reset and CONFIG_FILE.exists():
        try:
            CONFIG_FILE.unlink()
        except Exception:
            pass

    saved = load_saved_api_key()
    if saved:
        console.print(f"[dim]Saved Gemini key:[/dim] [cyan]{mask_key(saved)}[/cyan]")
        choice = Prompt.ask(
            "Press Enter to use saved key, or type 'update' to replace it",
            default="",
        ).strip().lower()
        if choice in ("update", "u", "new"):
            new_key = getpass("Enter new Gemini API Key: ").strip()
            if new_key:
                save_api_key(new_key)
                return new_key
            return saved
        return saved

    key = getpass("Enter your Gemini API Key: ").strip()
    if key:
        save_api_key(key)
        return key
    return None


# ---------------------------------------------------------------------------
# EXIF helpers
# ---------------------------------------------------------------------------


def _rational_to_float(value: Any) -> Optional[float]:
    try:
        if isinstance(value, tuple) and len(value) == 2:
            return float(value[0]) / float(value[1])
        return float(value)
    except Exception:
        return None


def _gps_coord_to_decimal(coord: Any, ref: Any) -> Optional[float]:
    try:
        degrees = _rational_to_float(coord[0])
        minutes = _rational_to_float(coord[1])
        seconds = _rational_to_float(coord[2])
        if degrees is None or minutes is None or seconds is None:
            return None
        decimal = degrees + minutes / 60.0 + seconds / 3600.0
        if str(ref).upper() in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None


def extract_exif(image_path: Path) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    try:
        with Image.open(image_path) as img:
            exif = img.getexif()
            if not exif:
                return result

            for tag_id, value in exif.items():
                tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="replace")
                    except Exception:
                        value = repr(value)
                if isinstance(value, (int, float, str)):
                    result[tag] = value

            try:
                exif_ifd_id = getattr(getattr(ExifTags, "IFD", None), "Exif", 0x8769)
                exif_ifd = exif.get_ifd(exif_ifd_id)
                for tag_id, value in exif_ifd.items():
                    tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if tag not in result and isinstance(value, (int, float, str)):
                        result[tag] = value
            except Exception:
                pass

            try:
                gps_ifd_id = getattr(getattr(ExifTags, "IFD", None), "GPSInfo", 0x8825)
                gps = exif.get_ifd(gps_ifd_id)
                if gps:
                    lat = _gps_coord_to_decimal(gps.get(2), gps.get(1))
                    lon = _gps_coord_to_decimal(gps.get(4), gps.get(3))
                    if lat is not None and lon is not None:
                        result["GPSLatitude"] = lat
                        result["GPSLongitude"] = lon
                    altitude = _rational_to_float(gps.get(6))
                    if altitude is not None:
                        result["GPSAltitude"] = round(altitude, 2)
            except Exception:
                pass
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Download / image helpers
# ---------------------------------------------------------------------------


def build_http_session(proxy_url: str = "") -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Referer": "https://www.instagram.com/",
            "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
        }
    )
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET"]),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}

    return session


def download_image(
    session: requests.Session, url: Optional[str], destination: Path
) -> Optional[Path]:
    if not url:
        return None
    try:
        response = session.get(url, timeout=60, stream=True)
        response.raise_for_status()
        destination.parent.mkdir(parents=True, exist_ok=True)
        with open(destination, "wb") as handle:
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if chunk:
                    handle.write(chunk)
        if destination.stat().st_size == 0:
            destination.unlink(missing_ok=True)
            return None
        return destination
    except Exception:
        destination.unlink(missing_ok=True)
        return None


def prepare_image_for_gemini(
    source: Path, output_dir: Path, index: int
) -> Optional[Path]:
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with Image.open(source) as img:
            img.thumbnail((1024, 1024))
            if img.mode != "RGB":
                img = img.convert("RGB")
            target = output_dir / f"gemini_{index:02d}.jpg"
            img.save(target, "JPEG", quality=85, optimize=True)
        return target
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Profile collection
# ---------------------------------------------------------------------------


def collect_profile_data(
    username: str,
    max_posts: int,
    max_images: int,
    temp_dir: Path,
    proxy_url: str,
    console: Console,
) -> Tuple[Dict[str, Any], List[Path]]:
    session = build_http_session(proxy_url)

    loader = instaloader.Instaloader(
        download_pictures=False,
        download_videos=False,
        download_video_thumbnails=False,
        save_metadata=False,
        post_metadata_txt_pattern="",
        max_connection_attempts=3,
        request_timeout=60,
    )

    # Route every Instaloader request through proxy
    apply_proxy_to_loader(loader, proxy_url)

    profile = Profile.from_username(loader.context, username)

    evidence: Dict[str, Any] = {
        "username": profile.username,
        "full_name": profile.full_name,
        "biography": profile.biography,
        "external_url": profile.external_url,
        "followers": profile.followers,
        "followees": profile.followees,
        "media_count": profile.mediacount,
        "is_private": profile.is_private,
        "is_verified": profile.is_verified,
        "profile_pic_url": profile.profile_pic_url,
        "highlights": [],
        "posts": [],
        "exif": [],
        "private_notice": None,
        "collection_errors": [],
        "proxy_used": proxy_url or None,
    }

    try:
        if hasattr(profile, "get_highlights"):
            highlights = list(profile.get_highlights())
            evidence["highlights"] = [
                getattr(item, "title", str(item)) for item in highlights[:10]
            ]
    except Exception:
        evidence["highlights"] = []

    gemini_dir = temp_dir / "gemini"
    gemini_images: List[Path] = []

    profile_pic_path = temp_dir / "profile_pic.jpg"
    downloaded_pic = download_image(session, profile.profile_pic_url, profile_pic_path)
    if downloaded_pic:
        exif = extract_exif(downloaded_pic)
        if exif:
            evidence["exif"].append({"source": "profile_picture", "metadata": exif})
        prepared = prepare_image_for_gemini(downloaded_pic, gemini_dir, len(gemini_images))
        if prepared:
            gemini_images.append(prepared)

    if profile.is_private:
        evidence["private_notice"] = (
            "Profile is private. Posts and media are not publicly accessible."
        )
        return evidence, gemini_images

    post_index = 0
    try:
        for post in profile.get_posts():
            if post_index >= max_posts:
                break

            post_record: Dict[str, Any] = {
                "shortcode": post.shortcode,
                "date_utc": (post.date_utc.isoformat() if post.date_utc else None),
                "caption": (post.caption or "")[:2000],
                "location": getattr(post.location, "name", None),
                "is_video": post.is_video,
                "typename": post.typename,
                "likes": getattr(post, "likes", None),
                "comments": getattr(post, "comments", None),
                "image_files": [],
            }

            image_urls: List[str] = []
            try:
                if post.typename == "GraphSidecar":
                    for node in post.get_sidecar_nodes():
                        if not node.is_video:
                            image_urls.append(node.display_url)
                            break
                elif not post.is_video:
                    image_urls.append(post.url)
            except Exception:
                if not post.is_video and getattr(post, "url", None):
                    image_urls.append(post.url)

            for img_index, image_url in enumerate(
                image_urls[: max(0, max_images - len(gemini_images))]
            ):
                dest = temp_dir / f"post_{post_index:03d}_{img_index}.jpg"
                downloaded = download_image(session, image_url, dest)
                if not downloaded:
                    continue

                post_record["image_files"].append(downloaded.name)

                exif = extract_exif(downloaded)
                if exif:
                    evidence["exif"].append(
                        {"source": f"post_{post.shortcode}_{img_index}", "metadata": exif}
                    )

                if len(gemini_images) < max_images:
                    prepared = prepare_image_for_gemini(downloaded, gemini_dir, len(gemini_images))
                    if prepared:
                        gemini_images.append(prepared)

            evidence["posts"].append(post_record)
            post_index += 1

    except InstaloaderException as exc:
        evidence["collection_errors"].append(f"Post collection: {exc}")
    except Exception as exc:
        evidence["collection_errors"].append(f"Unexpected post error: {exc}")

    return evidence, gemini_images


# ---------------------------------------------------------------------------
# Gemini analysis
# ---------------------------------------------------------------------------


def build_gemini_prompt(evidence: Dict[str, Any]) -> str:
    evidence_json = json.dumps(evidence, indent=2, ensure_ascii=False, default=str)

    return f"""You are an expert OSINT and geolocation analyst.
Analyze the following PUBLIC Instagram profile evidence and attached images.

Target username: @{evidence.get("username", "unknown")}

COLLECTED EVIDENCE (profile metadata, post captions, locations, EXIF/GPS):
{evidence_json}

ATTACHED IMAGES:
The images are profile pictures and recent public post images, resized for analysis.

YOUR TASK:
Perform a deep multimodal OSINT investigation. Examine both the text data and every attached image for origin/background clues.

Specifically check for:

1. DOCUMENTS & SIGNAGE (OCR):
   - Certificates, school/institution names, ID cards, badges.
   - Street signs, shop signs, banners, posters.
   - Local languages and scripts visible in images.
   - License plates, currency symbols, receipts.

2. VISUAL CLUES:
   - National/regional flags, emblems, club uniforms, sports team logos.
   - Currency, electrical outlets, plug types, architecture style.
   - Vehicle models, traffic signs, road markings.
   - Food packaging, brands, menus.

3. GEOGRAPHIC INDICATORS:
   - Landmarks, mountains, beaches, vegetation, weather patterns.
   - Building styles, religious structures, urban layout.
   - Sunlight/shadow direction if relevant.
   - GPS/EXIF coordinates if present.

4. TEXTUAL & BEHAVIORAL CLUES:
   - Bio language, captions, hashtags, location tags.
   - Writing style, slang, regional vocabulary.
   - Time patterns, holidays, cultural references.
   - External links and their likely region.

OUTPUT FORMAT:
Return ONLY a clean Markdown report with these exact sections:

# OSINT Investigation Report — @{evidence.get("username", "unknown")}

## 1. Profile Summary
A concise summary of the account.

## 2. Key Visual & Textual Evidence
Bullet points of the strongest clues, citing which image/post they came from.
Include OCR findings, signage, flags, documents, uniforms, etc.

## 3. Metadata / EXIF Findings
Summarize camera models, timestamps, GPS coordinates, software tags, and any other EXIF findings. If no EXIF is present, say so clearly.

## 4. Estimated Country / Region & Confidence
State the most likely country and region/city if possible.
Assign a confidence level: HIGH / MEDIUM / LOW.
Provide detailed reasoning that connects the evidence to the estimate.
Mention alternative possibilities if evidence is ambiguous.

## 5. Analyst Notes
Caveats, missing data, and recommended next steps.

RULES:
- Be specific. Cite exact captions, image content, or metadata values.
- Do not invent evidence. If something is uncertain, say "uncertain" or "not visible."
- Do not include generic disclaimers about privacy or ethics.
- Do not include any text outside the Markdown report.
"""


def analyze_with_gemini(
    api_key: str,
    evidence: Dict[str, Any],
    image_paths: List[Path],
    console: Console,
) -> str:
    prompt = build_gemini_prompt(evidence)

    contents: List[Any] = [prompt]
    for image_path in image_paths:
        try:
            contents.append(
                types.Part.from_bytes(
                    data=image_path.read_bytes(),
                    mime_type="image/jpeg",
                )
            )
        except Exception:
            continue

    client = genai.Client(api_key=api_key)
    config = types.GenerateContentConfig(temperature=0.2)

    last_error: Optional[Exception] = None
    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=contents,
                config=config,
            )
            text = getattr(response, "text", None)
            if text and text.strip():
                return text.strip()
            raise RuntimeError("Gemini returned an empty response.")
        except Exception as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(2 ** attempt)

    raise RuntimeError(f"Gemini analysis failed: {last_error}")


# ---------------------------------------------------------------------------
# Fallback report / output
# ---------------------------------------------------------------------------


def fallback_report(evidence: Dict[str, Any], error: str) -> str:
    username = evidence.get("username", "unknown")
    exif_count = len(evidence.get("exif", []))
    post_count = len(evidence.get("posts", []))

    lines = [
        f"# OSINT Investigation Report — @{username}",
        "",
        "## 1. Profile Summary",
        f"- **Username:** @{username}",
        f"- **Full Name:** {evidence.get('full_name') or 'N/A'}",
        f"- **Bio:** {evidence.get('biography') or 'N/A'}",
        f"- **External URL:** {evidence.get('external_url') or 'N/A'}",
        f"- **Followers:** {evidence.get('followers')}",
        f"- **Followees:** {evidence.get('followees')}",
        f"- **Media Count:** {evidence.get('media_count')}",
        f"- **Private:** {evidence.get('is_private')}",
        f"- **Proxy Used:** {evidence.get('proxy_used') or 'none'}",
        "",
        "## 2. Key Visual & Textual Evidence",
        f"- Posts collected: {post_count}",
        f"- EXIF records extracted: {exif_count}",
        "- Automated Gemini visual analysis was unavailable.",
        "",
        "## 3. Metadata / EXIF Findings",
    ]

    if evidence.get("exif"):
        for record in evidence["exif"][:10]:
            lines.append(
                f"- **{record.get('source')}:** "
                f"`{json.dumps(record.get('metadata', {}), ensure_ascii=False)}`"
            )
    else:
        lines.append("- No EXIF metadata found in downloaded images.")

    lines.extend(
        [
            "",
            "## 4. Estimated Country / Region & Confidence",
            "- **Confidence:** LOW",
            f"- Gemini analysis failed: `{error}`",
            "- No automated geographic estimate is available.",
            "",
            "## 5. Analyst Notes",
            "- Review the saved evidence JSON manually.",
            "- Retry with a valid Gemini API key for multimodal analysis.",
        ]
    )

    return "\n".join(lines)


def save_outputs(
    username: str,
    report_md: str,
    evidence: Dict[str, Any],
) -> Tuple[Path, Path]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    safe_username = re.sub(r"[^A-Za-z0-9_.-]", "_", username)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    report_path = OUTPUT_DIR / f"osint_{safe_username}_{stamp}.md"
    evidence_path = OUTPUT_DIR / f"osint_{safe_username}_{stamp}_evidence.json"

    report_path.write_text(report_md, encoding="utf-8")
    evidence_path.write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return report_path, evidence_path


# ---------------------------------------------------------------------------
# CLI / main
# ---------------------------------------------------------------------------


def print_evidence_summary(evidence: Dict[str, Any]) -> None:
    table = Table(
        title="Collected Evidence",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Field", style="dim")
    table.add_column("Value", overflow="fold")

    table.add_row("Username", f"@{evidence.get('username')}")
    table.add_row("Full Name", str(evidence.get("full_name") or "N/A"))
    table.add_row("Bio", (evidence.get("biography") or "N/A")[:180])
    table.add_row("External URL", str(evidence.get("external_url") or "N/A"))
    table.add_row("Followers", str(evidence.get("followers")))
    table.add_row("Posts Fetched", str(len(evidence.get("posts", []))))
    table.add_row("EXIF Records", str(len(evidence.get("exif", []))))
    table.add_row("Private", str(evidence.get("is_private")))
    table.add_row("Proxy Used", str(evidence.get("proxy_used") or "none"))

    if evidence.get("private_notice"):
        table.add_row("Notice", evidence["private_notice"])

    console.print(table)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="IG-OSINT — Public Instagram OSINT & geolocation analyzer with proxy IP masking."
    )
    parser.add_argument(
        "--username",
        help="Instagram username to analyze (skips interactive prompt).",
    )
    parser.add_argument(
        "--reset-key",
        action="store_true",
        help="Delete the saved Gemini API key and prompt for a new one.",
    )
    parser.add_argument(
        "--max-posts",
        type=int,
        default=8,
        help="Maximum number of recent posts to collect (default: 8).",
    )
    parser.add_argument(
        "--max-images",
        type=int,
        default=10,
        help="Maximum number of images to send to Gemini (default: 10).",
    )
    parser.add_argument(
        "--proxy",
        default=None,
        help="Proxy URL (e.g., socks5://127.0.0.1:9050). Skips interactive prompt.",
    )
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Disable proxy (traffic uses real IP).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    console.print(
        Panel(
            Align.center(BANNER),
            title=f"[bold cyan]{TOOL_NAME} v{VERSION}[/bold cyan]",
            subtitle="Public Instagram OSINT & Geolocation Engine",
            border_style="cyan",
            expand=True,
            width=console.width,
            padding=(0, 1),
        )
    )
    console.print(
        "[dim]For lawful analysis of public profiles only. "
        "Respect platform terms and local privacy laws.[/dim]\n"
    )

    # ---------- Proxy setup (interactive) ----------
    if args.no_proxy:
        proxy_url = ""
        console.print("[yellow]Proxy disabled (--no-proxy).[/yellow]")
    elif args.proxy:
        proxy_url = normalize_proxy(args.proxy)
        apply_proxy_env(proxy_url)
        exit_ip = verify_proxy(proxy_url)
        if exit_ip:
            console.print(
                f"[green]✓ Proxy (CLI):[/green] [cyan]{proxy_url}[/cyan] "
                f"[dim]→ exit IP {exit_ip}[/dim]"
            )
        else:
            console.print(
                f"[yellow]⚠ Proxy set via CLI but unverified: {proxy_url}[/yellow]"
            )
    else:
        proxy_url = prompt_proxy()
        apply_proxy_env(proxy_url)

    # ---------- Gemini API key (interactive) ----------
    console.print()
    api_key = resolve_api_key(reset=args.reset_key)
    if not api_key:
        console.print("[red]No Gemini API key provided. Exiting.[/red]")
        return 1

    # ---------- Target ID (interactive) ----------
    username = args.username or Prompt.ask(
        "Enter target Instagram ID"
    ).strip().lstrip("@")
    if not username:
        console.print("[red]No target username provided. Exiting.[/red]")
        return 1

    console.print(
        Panel(
            f"[bold]Target:[/bold] @{username}\n"
            f"[bold]Proxy:[/bold] {proxy_url or 'disabled (real IP)'}\n"
            f"[bold]Gemini key:[/bold] {mask_key(api_key)}",
            title="Session",
            border_style="cyan",
        )
    )

    temp_dir = Path(tempfile.mkdtemp(prefix="ig_osint_"))
    evidence: Dict[str, Any] = {}
    gemini_images: List[Path] = []

    try:
        with console.status(
            "[bold cyan]Fetching public profile, posts, and EXIF through proxy...[/bold cyan]",
            spinner="dots",
        ):
            evidence, gemini_images = collect_profile_data(
                username=username,
                max_posts=max(0, args.max_posts),
                max_images=max(0, args.max_images),
                temp_dir=temp_dir,
                proxy_url=proxy_url,
                console=console,
            )

        print_evidence_summary(evidence)

        if evidence.get("collection_errors"):
            console.print("\n[yellow]Collection warnings:[/yellow]")
            for warning in evidence["collection_errors"]:
                console.print(f"  [yellow]• {warning}[/yellow]")

        report_md: str
        try:
            with console.status(
                "[bold magenta]Running Gemini multimodal OSINT analysis...[/bold magenta]",
                spinner="dots12",
            ):
                report_md = analyze_with_gemini(
                    api_key=api_key,
                    evidence=evidence,
                    image_paths=gemini_images,
                    console=console,
                )
        except Exception as exc:
            console.print(f"\n[yellow]Gemini analysis unavailable: {exc}[/yellow]")
            report_md = fallback_report(evidence, str(exc))

        report_path, evidence_path = save_outputs(
            username=username,
            report_md=report_md,
            evidence=evidence,
        )

        console.rule("[bold green]FINAL OSINT REPORT[/bold green]")
        console.print(Markdown(report_md))

        console.print(
            Panel(
                f"[green]Report saved:[/green] {report_path}\n"
                f"[green]Evidence JSON:[/green] {evidence_path}",
                title="Archived",
                border_style="green",
            )
        )
        return 0

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        return 130
    except InstaloaderException as exc:
        console.print(f"[red]Instagram error:[/red] {exc}")
        return 1
    except requests.RequestException as exc:
        console.print(f"[red]Network error:[/red] {exc}")
        return 1
    except Exception as exc:
        console.print(f"[red]Unexpected error:[/red] {exc}")
        return 1
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
