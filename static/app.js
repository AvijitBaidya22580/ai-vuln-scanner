document.addEventListener('DOMContentLoaded', () => {
    // --- State Management ---
    let scanResults = null;
    let aiAnalysis = null;
    let currentTab = 'dashboard';

    // --- UI Elements ---
    const navItems = document.querySelectorAll('#sidebar-nav li');
    const tabContents = document.querySelectorAll('.tab-content');
    const pageTitle = document.getElementById('page-title');
    const pageDesc = document.getElementById('page-desc');

    const targetInput = document.getElementById('target-input');
    const scanBtn = document.getElementById('scan-btn');
    const scanProgress = document.getElementById('scan-progress');
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');
    const resultsGrid = document.getElementById('results-grid');

    const analyzeBtn = document.getElementById('analyze-btn');
    const aiOutput = document.getElementById('ai-output');

    const reportBtn = document.getElementById('report-btn');
    const reportOutput = document.getElementById('report-output');
    const downloadBtn = document.getElementById('download-btn');
    const printBtn = document.getElementById('print-btn');

    // AI Modal Elements
    const aiModalOverlay = document.getElementById('ai-modal-overlay');
    const openAiChat = document.getElementById('open-ai-chat');
    const closeAiModal = document.getElementById('close-ai-modal');
    const chatInput = document.getElementById('chat-input');
    const chatSend = document.getElementById('chat-send');
    const chatMessages = document.getElementById('chat-messages');

    // --- Tab Navigation ---
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const tabId = item.getAttribute('data-tab');
            switchTab(tabId);
        });
    });

    function switchTab(tabId) {
        currentTab = tabId;
        navItems.forEach(nav => nav.classList.toggle('active', nav.getAttribute('data-tab') === tabId));
        tabContents.forEach(content => content.classList.toggle('active', content.id === tabId));

        const titles = {
            'dashboard': ['Security Dashboard', 'External Reconnaissance & Vulnerability Assessment'],
            'analysis': ['AI Vulnerability Analysis', 'Intelligent Interpretation of Scan Results'],
            'report': ['Final Security Report', 'Professional Assessment Documentation']
        };
        pageTitle.textContent = titles[tabId][0];
        pageDesc.textContent = titles[tabId][1];
    }

    // --- Modal Logic ---
    openAiChat.addEventListener('click', () => aiModalOverlay.classList.add('active'));
    closeAiModal.addEventListener('click', () => aiModalOverlay.classList.remove('active'));
    aiModalOverlay.addEventListener('click', (e) => {
        if (e.target === aiModalOverlay) aiModalOverlay.classList.remove('active');
    });

    // --- Scan Logic ---
    scanBtn.addEventListener('click', async () => {
        const target = targetInput.value.trim();
        if (!target) return alert('Please enter a target URL or domain.');

        scanResults = null;
        resultsGrid.innerHTML = '';
        scanProgress.classList.remove('hidden');
        scanBtn.disabled = true;
        updateProgress(10, 'Resolving target host...');

        try {
            const response = await fetch('/api/recon', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target })
            });

            if (!response.ok) throw new Error(await response.text());

            updateProgress(60, 'Analyzing services and headers...');
            scanResults = await response.json();
            
            updateProgress(100, 'Scan complete.');
            renderResults(scanResults);
            analyzeBtn.disabled = false;
        } catch (error) {
            console.error(error);
            progressText.textContent = 'Scan failed: ' + error.message;
            progressText.style.color = 'var(--accent-red)';
        } finally {
            scanBtn.disabled = false;
            setTimeout(() => scanProgress.classList.add('hidden'), 3000);
        }
    });

    function updateProgress(percent, text) {
        progressFill.style.width = percent + '%';
        progressText.textContent = text;
    }

    // --- Icons ---
    const ICONS = {
        target: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="6"></circle><circle cx="12" cy="12" r="2"></circle></svg>`,
        ports: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="15" rx="2" ry="2"></rect><polyline points="17 2 12 7 7 2"></polyline></svg>`,
        headers: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"></path></svg>`,
        ssl: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`,
        tech: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>`,
        subdomains: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>`
    };

    function renderResults(data) {
        const modules = [
            { id: 'target', title: 'Target Host', icon: ICONS.target, content: renderTargetInfo(data) },
            { id: 'ports', title: 'Open Ports', icon: ICONS.ports, content: renderPortScan(data.port_scan) },
            { id: 'headers', title: 'Security Headers', icon: ICONS.headers, content: renderHeaderAudit(data.http_analysis.security_audit) },
            { id: 'ssl', title: 'SSL/TLS Status', icon: ICONS.ssl, content: renderSSLInfo(data.ssl_tls) },
            { id: 'tech', title: 'Technologies', icon: ICONS.tech, content: renderTechStack(data.technologies) },
            { id: 'subs', title: 'Subdomains', icon: ICONS.subdomains, content: renderSubdomains(data.subdomains) }
        ];

        resultsGrid.innerHTML = modules.map(m => `
            <div class="module-card">
                <div class="module-header">
                    <div class="module-title">${m.icon} ${m.title}</div>
                </div>
                <div class="module-body">${m.content}</div>
            </div>
        `).join('');
    }

    // --- Renderers ---
    function renderTargetInfo(data) {
        return `<table>
            <tr><th>Domain</th><td>${data.target}</td></tr>
            <tr><th>IP</th><td>${data.resolved_ip}</td></tr>
            <tr><th>Time</th><td>${data.scan_time.split(' ')[1]}</td></tr>
        </table>`;
    }

    function renderPortScan(ports) {
        if (!ports.length) return '<div class="empty-state">No open common ports.</div>';
        return `<table><thead><tr><th>Port</th><th>Service</th></tr></thead><tbody>
            ${ports.map(p => `<tr><td>${p.port}</td><td>${p.service}</td></tr>`).join('')}
        </tbody></table>`;
    }

    function renderHeaderAudit(audit) {
        if (!audit?.length) return '<div class="empty-state">No header data.</div>';
        return `<table><tbody>
            ${audit.map(h => `<tr><td>${h.header}</td><td class="${h.present ? 'severity-info' : 'severity-high'}">${h.present ? '✅' : '❌'}</td></tr>`).join('')}
        </tbody></table>`;
    }

    function renderSSLInfo(ssl) {
        if (ssl.error) return `<div class="severity-high">SSL Error</div>`;
        return `<table>
            <tr><th>Exp</th><td class="${ssl.expired ? 'severity-high' : ''}">${ssl.not_after.split(' ')[0]}</td></tr>
            <tr><th>Days</th><td>${ssl.days_until_expiry}</td></tr>
        </table>`;
    }

    function renderTechStack(techs) {
        if (!techs.length) return '<div class="empty-state">None detected.</div>';
        return techs.slice(0, 5).map(t => `<div class="tech-tag">${t.name}</div>`).join('');
    }

    function renderSubdomains(subs) {
        if (!subs.length) return '<div class="empty-state">None found.</div>';
        return `<table><tbody>
            ${subs.slice(0, 5).map(s => `<tr><td>${s.subdomain}</td></tr>`).join('')}
        </tbody></table>`;
    }

    // --- AI Logic ---
    analyzeBtn.addEventListener('click', async () => {
        if (!scanResults) return;
        analyzeBtn.disabled = true;
        aiOutput.innerHTML = '<div class="loading-spinner">Llama 3.2 is analyzing findings...</div>';
        switchTab('analysis');

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recon_data: scanResults })
            });
            const data = await response.json();
            aiAnalysis = data.analysis;
            aiOutput.innerHTML = marked.parse(aiAnalysis);
            reportBtn.disabled = false;
        } catch (error) {
            aiOutput.innerHTML = `<div class="severity-high">Analysis error</div>`;
        } finally {
            analyzeBtn.disabled = false;
        }
    });

    // --- Report Logic ---
    reportBtn.addEventListener('click', async () => {
        if (!scanResults || !aiAnalysis) return;
        reportBtn.disabled = true;
        reportOutput.innerHTML = '<div class="loading-spinner">Building security report...</div>';
        switchTab('report');

        try {
            const response = await fetch('/api/report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recon_data: scanResults, analysis: aiAnalysis })
            });
            const data = await response.json();
            reportOutput.innerHTML = `<div class="report-body markdown-body">${marked.parse(data.report)}</div>`;
            downloadBtn.classList.remove('hidden');
            printBtn.classList.remove('hidden');
            downloadBtn.onclick = () => {
                const blob = new Blob([data.report], { type: 'text/markdown' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url; a.download = `Report_${scanResults.target}.md`; a.click();
            };
            printBtn.onclick = () => window.print();
        } catch (error) {
            reportOutput.innerHTML = `<div class="severity-high">Report error</div>`;
        } finally {
            reportBtn.disabled = false;
        }
    });

    // --- Chat Logic ---
    async function sendChatMessage() {
        const message = chatInput.value.trim();
        if (!message) return;
        appendMessage('user', message);
        chatInput.value = '';

        try {
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    message, 
                    context: aiAnalysis || (scanResults ? JSON.stringify(scanResults) : "")
                })
            });
            const data = await response.json();
            appendMessage('ai', data.reply);
        } catch (error) {
            appendMessage('ai', 'Error: ' + error.message);
        }
    }

    function appendMessage(role, text) {
        const msgDiv = document.createElement('div');
        msgDiv.className = `message ${role}`;
        msgDiv.innerHTML = `<div class="msg-avatar">${role === 'ai' ? 'AI' : 'U'}</div><div class="msg-content">${marked.parse(text)}</div>`;
        chatMessages.appendChild(msgDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    chatSend.addEventListener('click', sendChatMessage);
    chatInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') sendChatMessage(); });
});
