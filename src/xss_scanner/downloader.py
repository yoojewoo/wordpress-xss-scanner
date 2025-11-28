"""
워드프레스 플러그인을 검색/다운로드/압축해제 하는 모듈.

원본 plugin_down.py 를 모듈화 한 것이다.
"""

import concurrent.futures
import os
import random
import threading
import time
import zipfile

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# 컬러 출력용
colors = [
    '\033[91m',
    '\033[92m',
    '\033[93m',
    '\033[94m',
    '\033[95m',
    '\033[96m',
    '\033[90m',
    '\033[97m',
    '\033[91m',
    '\033[92m',
]
RESET = '\033[0m'

save_dir = "./plugins"
_tmp_suffix = ".part"
_folder_lock = threading.Lock()  # 중복 다운로드 방지(임계영역 보호)


def ensure_directory(directory: str):
    if not os.path.exists(directory):
        os.makedirs(directory)


def get_existing_folders(base_dir: str):
    if not os.path.exists(base_dir):
        return []
    out = []
    for name in os.listdir(base_dir):
        p = os.path.join(base_dir, name)
        if os.path.isdir(p):
            out.append(name)
        elif name.lower().endswith(".zip"):
            out.append(name.rsplit('.', 1)[0])
    return out


def create_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/58.0.3029.110 Safari/537.3"
            )
        }
    )
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.verify = True
    return s


def _safe_basename(name: str) -> str:
    base = os.path.basename(name)
    safe = "".join(c for c in base if c.isalnum() or c in "-_.")
    return safe or ("plugin_" + str(int(time.time())))


def _is_safe_member(dest_dir: str, member: str) -> bool:
    dest_abs = os.path.abspath(dest_dir)
    target = os.path.abspath(os.path.join(dest_dir, member))
    if os.path.isabs(member):
        return False
    if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
        return False
    if ".." in os.path.normpath(member).split(os.sep):
        return False
    return True


def safe_extract_zip(zip_path: str, dest_dir: str):
    ensure_directory(dest_dir)
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for m in zf.namelist():
            if _is_safe_member(dest_dir, m):
                zf.extract(m, dest_dir)
            else:
                print(f"[warn] skip unsafe path in zip: {m}")


def download_plugin(link: str, existing_folders, session: requests.Session) -> int:
    """
    개별 플러그인 상세 페이지 링크에서 실제 zip을 다운로드 & 압축해제.
    """
    try:
        resp = session.get(link, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        print(f"Error fetching plugin page {link}: {e}")
        return 0

    soup = BeautifulSoup(resp.content, 'html.parser')
    download_anchor = soup.find('a', {'class': 'plugin-download button download-button button-large'})
    if not download_anchor:
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith("https://downloads.wordpress.org/plugin/") and href.endswith(".zip"):
                download_anchor = a
                break
    if not download_anchor:
        print(f"Download link not found for {link}")
        return 0

    download_link = download_anchor['href']
    file_name = _safe_basename(download_link.split('/')[-1])
    folder_name = file_name.rsplit('.', 1)[0]

    with _folder_lock:
        if folder_name in existing_folders:
            print(f"Skipping {folder_name} as it already exists.")
            return 0
        existing_folders.append(folder_name)

    ensure_directory(save_dir)
    final_path = os.path.join(save_dir, file_name)
    temp_path = final_path + _tmp_suffix
    extract_dir = os.path.join(save_dir, folder_name)

    try:
        with session.get(download_link, stream=True, timeout=30) as r:
            r.raise_for_status()
            with open(temp_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=1024 * 256):
                    if chunk:
                        f.write(chunk)
        os.replace(temp_path, final_path)
        print('Downloaded:', file_name)

        try:
            if zipfile.is_zipfile(final_path):
                safe_extract_zip(final_path, extract_dir)
                print('Extracted to:', extract_dir)
                try:
                    os.remove(final_path)
                    print('Removed zip:', final_path)
                except Exception as rm_err:
                    print(f"[warn] failed to remove zip {final_path}: {rm_err}")
            else:
                print(f"[warn] not a zip file: {final_path}")
        except Exception as ex:
            print(f"[warn] extract failed for {final_path}: {ex}")

    except Exception as e:
        print(f"Error downloading plugin from {download_link}: {e}")
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass
        with _folder_lock:
            if folder_name in existing_folders:
                existing_folders.remove(folder_name)
        return 0

    time.sleep(random.uniform(0.5, 2))
    return 1


def download_plugins_on_page(
    page_num: int,
    existing_folders,
    target: str,
    session: requests.Session,
    max_plugins=None,
    counter=None,
):
    """
    검색 결과 페이지 하나에서 플러그인 상세 링크들을 모아
    병렬로 download_plugin 을 호출.
    """
    base_url = f"https://ko.wordpress.org/plugins/search/{target}/page/"
    url = base_url + str(page_num)
    try:
        resp = session.get(url, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        print(f"Error fetching search page {url}: {e}")
        return []

    soup = BeautifulSoup(resp.content, 'html.parser')
    entries = soup.find_all('h3', {'class': 'entry-title'})
    if not entries:
        return []

    links = [e.find('a')['href'] for e in entries if e.find('a')]

    # 갯수 제한(max_plugins)이 있으면 초과 시 stop
    if max_plugins and counter is not None:
        remaining = max_plugins - counter[0]
        if remaining <= 0:
            return []
        links = links[:remaining]

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures = [ex.submit(download_plugin, link, existing_folders, session) for link in links]
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if counter is not None:
                counter[0] += result

    time.sleep(random.uniform(1, 3))
    return links


def download_plugins_for_target(
    target: str,
    existing_folders,
    color_code: str,
    session: requests.Session,
    max_plugins=None,
):
    """
    특정 키워드에 대해 여러 페이지(최대 50페이지)에서 플러그인을 다운로드.
    """
    page = 1
    counter = [0]
    while True:
        links = download_plugins_on_page(page, existing_folders, target, session, max_plugins, counter)
        if not links:
            break
        print(f'{color_code}Downloaded {len(links)} plugins from page {page} for {target}.{RESET}')
        page += 1
        if max_plugins and counter[0] >= max_plugins:
            break
        if page > 50:
            break


def download_plugins_for_keywords(keywords, max_plugins=None):
    """
    여러 키워드에 대해 병렬로 플러그인을 다운로드하는 상위 함수.
    scripts/download_plugins.py 에서 사용.
    """
    ensure_directory(save_dir)
    existing_folders = get_existing_folders(save_dir)

    print("키워드에 대한 플러그인을 다운로드 합니다.")
    print("-------------------------------------------------")
    for i, t in enumerate(keywords):
        print(f'{i + 1}. {colors[i % len(colors)]}{t}{RESET}')
    print("-------------------------------------------------\n")

    session = create_session()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(
                download_plugins_for_target,
                t,
                existing_folders,
                colors[i % len(colors)],
                session,
                max_plugins,
            )
            for i, t in enumerate(keywords)
        ]
        for _ in concurrent.futures.as_completed(futures):
            pass


def interactive_cli():
    """
    직접 실행 시 사용할 수 있는 간단한 CLI.
    (scripts/download_plugins.py 에서도 쓸 수 있다.)
    """
    ensure_directory(save_dir)
    targets = input("키워드 입력 : ").split()[:10]
    limit = input("다운로드 최대 갯수(없으면 엔터): ").strip()
    max_plugins = int(limit) if limit.isdigit() else None

    download_plugins_for_keywords(targets, max_plugins=max_plugins)
