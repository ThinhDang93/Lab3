"""
Bài tập 15 - Crawling indriver.com
Môn: Bảo mật web và ứng dụng - Lab 3 Reconnaissance

Thu thập: emails, links, external_files, js_files, form_fields,
          images, videos, audio, comments

Chạy:  scrapy runspider recon_spider.py
Output: indriver_recon.json
"""
import scrapy
import re
import json
from urllib.parse import urljoin, urlparse


class ReconSpider(scrapy.Spider):
    name = "recon"
    start_urls = ["https://indriver.com"]

    custom_settings = {
        "DEPTH_LIMIT": 2,            # độ sâu crawl (tăng nếu muốn phủ rộng hơn)
        "ROBOTSTXT_OBEY": True,      # tôn trọng robots.txt
        "CONCURRENT_REQUESTS": 8,
        "DOWNLOAD_DELAY": 0.5,       # delay tránh DoS trang (đề nhắc)
        "USER_AGENT": "Mozilla/5.0 (recon-lab; educational)",
        "LOG_LEVEL": "INFO",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data = {k: set() for k in [
            "emails", "links", "external_files", "js_files",
            "form_fields", "images", "videos", "audio", "comments",
        ]}
        self.base_netloc = urlparse(self.start_urls[0]).netloc

    def parse(self, response):
        # chỉ xử lý HTML
        ctype = response.headers.get("Content-Type", b"").decode(errors="ignore")
        if "text/html" not in ctype:
            return

        body = response.text

        # emails
        for e in re.findall(r"[\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,}", body):
            self.data["emails"].add(e)

        # HTML comments
        for c in re.findall(r"<!--(.*?)-->", body, re.DOTALL):
            c = c.strip()
            if c:
                self.data["comments"].add(c)

        # links (tất cả <a href>)
        for href in response.css("a::attr(href)").getall():
            self.data["links"].add(urljoin(response.url, href))

        # js files
        for src in response.css("script::attr(src)").getall():
            self.data["js_files"].add(urljoin(response.url, src))

        # images
        for src in response.css("img::attr(src)").getall():
            self.data["images"].add(urljoin(response.url, src))

        # video / audio
        for src in response.css("video::attr(src), video source::attr(src)").getall():
            self.data["videos"].add(urljoin(response.url, src))
        for src in response.css("audio::attr(src), audio source::attr(src)").getall():
            self.data["audio"].add(urljoin(response.url, src))

        # form fields
        for name in response.css(
            "input::attr(name), textarea::attr(name), select::attr(name)"
        ).getall():
            self.data["form_fields"].add(name)

        # external files (link tới .pdf .doc .xls .zip ...)
        ext_pat = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|zip|rar|csv|txt)(\?|$)", re.I)
        for href in response.css("a::attr(href)").getall():
            full = urljoin(response.url, href)
            if ext_pat.search(full):
                self.data["external_files"].add(full)

        # tiếp tục crawl các link cùng domain
        for href in response.css("a::attr(href)").getall():
            full = urljoin(response.url, href)
            if urlparse(full).netloc == self.base_netloc:
                yield response.follow(full, callback=self.parse)

    def closed(self, reason):
        out = {k: sorted(v) for k, v in self.data.items()}
        with open("indriver_recon.json", "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        self.logger.info("Saved indriver_recon.json")
        for k, v in out.items():
            self.logger.info(f"  {k}: {len(v)}")
