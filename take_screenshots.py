"""
Playwright automation script to capture screenshots of the AI Vulnerability Scanner.
Navigates through the app, runs a scan for tryhackme.com (or uses cached results),
and captures 4 screenshots.
"""

import asyncio
import os
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = r"K:\my_ai\ai_vuln_scanner\screenshots"
BASE_URL = "http://localhost:8000"
TARGET_URL = "http://localhost:8000/static/index.html"

os.makedirs(SCREENSHOTS_DIR, exist_ok=True)


async def wait_for_selector_with_timeout(page, selector, timeout=10000):
    try:
        await page.wait_for_selector(selector, timeout=timeout)
        return True
    except Exception:
        return False


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
        context = await browser.new_context(viewport={"width": 1440, "height": 900})
        page = await context.new_page()

        print(f"Navigating to {TARGET_URL}...")
        await page.goto(TARGET_URL, wait_until="networkidle", timeout=30000)
        await asyncio.sleep(2)

        # -------------------------------------------------------
        # Step 1: Type target and start scan
        # -------------------------------------------------------
        print("Entering tryhackme.com in scan input...")
        # Try to find the input field
        input_selectors = [
            "input[placeholder*='domain']",
            "input[placeholder*='Domain']",
            "input[placeholder*='Enter']",
            "input[placeholder*='URL']",
            "input[placeholder*='target']",
            "input[type='text']",
            "#target",
            "#domain",
            "#scanTarget",
            ".scan-input",
        ]
        
        input_found = False
        for sel in input_selectors:
            try:
                el = page.locator(sel).first
                if await el.is_visible(timeout=2000):
                    await el.click()
                    await el.fill("")
                    await el.type("tryhackme.com")
                    print(f"  Found input with selector: {sel}")
                    input_found = True
                    break
            except Exception:
                continue
        
        if not input_found:
            print("  Could not find input by selector, trying to find all inputs...")
            inputs = await page.query_selector_all("input")
            for inp in inputs:
                try:
                    visible = await inp.is_visible()
                    if visible:
                        await inp.click()
                        await inp.fill("tryhackme.com")
                        print("  Filled first visible input")
                        input_found = True
                        break
                except Exception:
                    continue

        await asyncio.sleep(1)

        # Click the Start Scan button
        print("Clicking START SCAN button...")
        button_selectors = [
            "button:has-text('START SCAN')",
            "button:has-text('Start Scan')",
            "button:has-text('SCAN')",
            "button:has-text('Scan')",
            "button[type='submit']",
            ".scan-btn",
            "#startScan",
            "#scanBtn",
        ]
        
        btn_clicked = False
        for sel in button_selectors:
            try:
                btn = page.locator(sel).first
                if await btn.is_visible(timeout=2000):
                    await btn.click()
                    print(f"  Clicked button with selector: {sel}")
                    btn_clicked = True
                    break
            except Exception:
                continue
        
        if not btn_clicked:
            print("  Could not find button, trying all buttons...")
            buttons = await page.query_selector_all("button")
            for btn in buttons:
                try:
                    text = await btn.inner_text()
                    visible = await btn.is_visible()
                    if visible and ("scan" in text.lower() or "start" in text.lower()):
                        await btn.click()
                        print(f"  Clicked button: {text}")
                        btn_clicked = True
                        break
                except Exception:
                    continue

        # -------------------------------------------------------
        # Step 2: Wait for scan to complete (up to 90 seconds)
        # -------------------------------------------------------
        print("Waiting for scan results (up to 90 seconds)...")
        scan_complete = False
        completion_indicators = [
            ".scan-results",
            ".results-container",
            "#scanResults",
            ".result-card",
            ".vulnerability-list",
            ".security-score",
            "[class*='result']",
            "[class*='scan-complete']",
            ".dashboard-content",
            ".score",
        ]
        
        for attempt in range(18):  # 18 * 5 = 90 seconds
            await asyncio.sleep(5)
            print(f"  Checking attempt {attempt + 1}/18...")
            
            for indicator in completion_indicators:
                try:
                    el = page.locator(indicator).first
                    if await el.is_visible(timeout=1000):
                        print(f"  Found result indicator: {indicator}")
                        scan_complete = True
                        break
                except Exception:
                    continue
            
            if scan_complete:
                break
            
            # Also check if any content appeared on page
            try:
                content = await page.content()
                if "tryhackme" in content.lower() and any(
                    kw in content.lower() for kw in ["vulnerability", "ssl", "header", "score", "risk"]
                ):
                    print("  Found scan-related content in page")
                    scan_complete = True
                    break
            except Exception:
                pass

        if not scan_complete:
            print("  Scan may still be running or results not detected — taking screenshot anyway")

        await asyncio.sleep(3)

        # -------------------------------------------------------
        # Screenshot 1: Dashboard scan results
        # -------------------------------------------------------
        print("\nTaking screenshot 1: Dashboard scan results...")
        screenshot_path = os.path.join(SCREENSHOTS_DIR, "01_dashboard_scan_results.png")
        await page.screenshot(path=screenshot_path, full_page=False)
        print(f"  Saved: {screenshot_path}")

        # -------------------------------------------------------
        # Screenshot 2: Scroll down to see details panels
        # -------------------------------------------------------
        print("\nScrolling down to show Security Headers, SSL/TLS, Technologies, Subdomains panels...")
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
        await asyncio.sleep(2)
        
        screenshot_path = os.path.join(SCREENSHOTS_DIR, "02_dashboard_details.png")
        await page.screenshot(path=screenshot_path, full_page=False)
        print(f"  Saved: {screenshot_path}")

        # -------------------------------------------------------
        # Step 3: Navigate to AI Analysis
        # -------------------------------------------------------
        print("\nNavigating to AI Analysis tab...")
        ai_nav_selectors = [
            "a:has-text('AI Analysis')",
            "nav a:has-text('AI')",
            "li:has-text('AI Analysis')",
            "[href*='ai']",
            ".nav-item:has-text('AI')",
            "#aiAnalysis",
            "button:has-text('AI Analysis')",
        ]
        
        nav_clicked = False
        for sel in ai_nav_selectors:
            try:
                el = page.locator(sel).first
                if await el.is_visible(timeout=2000):
                    await el.click()
                    print(f"  Clicked AI Analysis nav with: {sel}")
                    nav_clicked = True
                    break
            except Exception:
                continue
        
        if not nav_clicked:
            print("  Trying all nav links for AI Analysis...")
            links = await page.query_selector_all("a, button, li")
            for link in links:
                try:
                    text = await link.inner_text()
                    if "ai" in text.lower() and ("analysis" in text.lower() or "insight" in text.lower()):
                        visible = await link.is_visible()
                        if visible:
                            await link.click()
                            print(f"  Clicked: {text}")
                            nav_clicked = True
                            break
                except Exception:
                    continue

        await asyncio.sleep(2)
        await page.evaluate("window.scrollTo(0, 0)")

        # Click "GENERATE AI INSIGHTS" button
        print("Clicking GENERATE AI INSIGHTS button...")
        insights_btn_selectors = [
            "button:has-text('GENERATE AI INSIGHTS')",
            "button:has-text('Generate AI Insights')",
            "button:has-text('AI INSIGHTS')",
            "button:has-text('Generate Insights')",
            "button:has-text('ANALYZE')",
            "button:has-text('Analyze')",
            "#generateInsights",
            ".ai-btn",
        ]
        
        insights_clicked = False
        for sel in insights_btn_selectors:
            try:
                btn = page.locator(sel).first
                if await btn.is_visible(timeout=2000):
                    await btn.click()
                    print(f"  Clicked insights button: {sel}")
                    insights_clicked = True
                    break
            except Exception:
                continue
        
        if not insights_clicked:
            print("  Trying all buttons for AI generation...")
            buttons = await page.query_selector_all("button")
            for btn in buttons:
                try:
                    text = await btn.inner_text()
                    visible = await btn.is_visible()
                    if visible and any(kw in text.lower() for kw in ["generate", "insight", "ai", "analyze"]):
                        await btn.click()
                        print(f"  Clicked button: {text}")
                        insights_clicked = True
                        break
                except Exception:
                    continue

        # Wait for AI analysis text to appear (up to 120 seconds)
        print("Waiting for AI analysis text (up to 120 seconds)...")
        ai_complete = False
        for attempt in range(24):  # 24 * 5 = 120 seconds
            await asyncio.sleep(5)
            print(f"  Checking attempt {attempt + 1}/24...")
            try:
                content = await page.content()
                if any(kw in content.lower() for kw in ["vulnerability", "recommendation", "risk assessment", "analysis complete", "security analysis"]):
                    # Check if a text block appeared
                    ai_indicators = [
                        ".ai-result",
                        ".analysis-result",
                        ".ai-content",
                        "#aiResult",
                        ".insight",
                        ".analysis-text",
                        "pre",
                    ]
                    for ind in ai_indicators:
                        try:
                            el = page.locator(ind).first
                            if await el.is_visible(timeout=1000):
                                txt = await el.inner_text()
                                if len(txt) > 50:
                                    print(f"  AI analysis content found ({len(txt)} chars)")
                                    ai_complete = True
                                    break
                        except Exception:
                            continue
                    
                    if not ai_complete and len(content) > 5000:
                        ai_complete = True
                        print("  AI analysis content appears to have loaded")
            except Exception:
                pass
            
            if ai_complete:
                break

        await asyncio.sleep(2)

        # -------------------------------------------------------
        # Screenshot 3: AI Analysis
        # -------------------------------------------------------
        print("\nTaking screenshot 3: AI Analysis...")
        screenshot_path = os.path.join(SCREENSHOTS_DIR, "03_ai_analysis.png")
        await page.screenshot(path=screenshot_path, full_page=False)
        print(f"  Saved: {screenshot_path}")

        # -------------------------------------------------------
        # Step 4: Navigate to Report
        # -------------------------------------------------------
        print("\nNavigating to Report tab...")
        report_nav_selectors = [
            "a:has-text('Report')",
            "nav a:has-text('Report')",
            "li:has-text('Report')",
            "[href*='report']",
            ".nav-item:has-text('Report')",
            "#report",
            "button:has-text('Report')",
        ]
        
        report_nav_clicked = False
        for sel in report_nav_selectors:
            try:
                el = page.locator(sel).first
                if await el.is_visible(timeout=2000):
                    await el.click()
                    print(f"  Clicked Report nav with: {sel}")
                    report_nav_clicked = True
                    break
            except Exception:
                continue
        
        if not report_nav_clicked:
            print("  Trying all nav links for Report...")
            links = await page.query_selector_all("a, button, li")
            for link in links:
                try:
                    text = await link.inner_text()
                    if text.strip().lower() == "report" or text.strip().lower() == "reports":
                        visible = await link.is_visible()
                        if visible:
                            await link.click()
                            print(f"  Clicked: {text}")
                            report_nav_clicked = True
                            break
                except Exception:
                    continue

        await asyncio.sleep(2)
        await page.evaluate("window.scrollTo(0, 0)")

        # Click "CREATE FULL REPORT" button
        print("Clicking CREATE FULL REPORT button...")
        report_btn_selectors = [
            "button:has-text('CREATE FULL REPORT')",
            "button:has-text('Create Full Report')",
            "button:has-text('GENERATE REPORT')",
            "button:has-text('Generate Report')",
            "button:has-text('CREATE REPORT')",
            "#generateReport",
            ".report-btn",
        ]
        
        report_btn_clicked = False
        for sel in report_btn_selectors:
            try:
                btn = page.locator(sel).first
                if await btn.is_visible(timeout=2000):
                    await btn.click()
                    print(f"  Clicked report button: {sel}")
                    report_btn_clicked = True
                    break
            except Exception:
                continue
        
        if not report_btn_clicked:
            print("  Trying all buttons for report generation...")
            buttons = await page.query_selector_all("button")
            for btn in buttons:
                try:
                    text = await btn.inner_text()
                    visible = await btn.is_visible()
                    if visible and any(kw in text.lower() for kw in ["report", "create", "generate"]):
                        await btn.click()
                        print(f"  Clicked button: {text}")
                        report_btn_clicked = True
                        break
                except Exception:
                    continue

        # Wait for report to generate (up to 120 seconds)
        print("Waiting for report to generate (up to 120 seconds)...")
        report_complete = False
        for attempt in range(24):
            await asyncio.sleep(5)
            print(f"  Checking attempt {attempt + 1}/24...")
            try:
                content = await page.content()
                report_indicators = [
                    ".report-content",
                    ".report-result",
                    "#reportContent",
                    ".report-body",
                    ".report-generated",
                ]
                for ind in report_indicators:
                    try:
                        el = page.locator(ind).first
                        if await el.is_visible(timeout=1000):
                            print(f"  Report content found: {ind}")
                            report_complete = True
                            break
                    except Exception:
                        continue
                
                if not report_complete:
                    if any(kw in content.lower() for kw in ["executive summary", "vulnerability report", "full report", "scan report"]):
                        print("  Report content detected in page source")
                        report_complete = True
            except Exception:
                pass
            
            if report_complete:
                break

        await asyncio.sleep(2)

        # -------------------------------------------------------
        # Screenshot 4: Report
        # -------------------------------------------------------
        print("\nTaking screenshot 4: Report...")
        screenshot_path = os.path.join(SCREENSHOTS_DIR, "04_report.png")
        await page.screenshot(path=screenshot_path, full_page=False)
        print(f"  Saved: {screenshot_path}")

        await browser.close()
        print("\n=== All 4 screenshots captured successfully ===")
        print(f"Screenshots saved in: {SCREENSHOTS_DIR}")


if __name__ == "__main__":
    asyncio.run(main())
