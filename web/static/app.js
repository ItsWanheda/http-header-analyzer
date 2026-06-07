document.addEventListener('DOMContentLoaded', () => {
    // Initialize Matrix Background
    initMatrix();
    
    // Initialize Eye Tracking
    initEyeTracking();
    
    // Initialize Form
    initForm();
});

function initMatrix() {
    const canvas = document.getElementById('matrix');
    const ctx = canvas.getContext('2d');

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const katakana = 'アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビピウゥクスツヌフムユュルグズブヅプエェケセテネヘメレヱゲゼデベペオォコソトノホモヨョロヲゴゾドボポヴッン';
    const latin = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const nums = '0123456789';
    const alphabet = katakana + latin + nums;

    const fontSize = 16;
    const columns = canvas.width / fontSize;

    const rainDrops = [];

    for (let x = 0; x < columns; x++) {
        rainDrops[x] = 1;
    }

    const draw = () => {
        ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.fillStyle = '#0F0';
        ctx.font = fontSize + 'px monospace';

        for (let i = 0; i < rainDrops.length; i++) {
            const text = alphabet.charAt(Math.floor(Math.random() * alphabet.length));
            ctx.fillText(text, i * fontSize, rainDrops[i] * fontSize);

            if (rainDrops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                rainDrops[i] = 0;
            }
            rainDrops[i]++;
        }
    };

    setInterval(draw, 30);

    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

function initEyeTracking() {
    const eyeContainer = document.querySelector('.eye-container');
    const pupil = document.querySelector('.pupil');

    document.addEventListener('mousemove', (e) => {
        const eyeRect = eyeContainer.getBoundingClientRect();
        const eyeCenterX = eyeRect.left + eyeRect.width / 2;
        const eyeCenterY = eyeRect.top + eyeRect.height / 2;

        const angle = Math.atan2(e.clientY - eyeCenterY, e.clientX - eyeCenterX);
        const distance = Math.min(
            Math.hypot(e.clientX - eyeCenterX, e.clientY - eyeCenterY) / 10,
            15
        );

        const pupilX = Math.cos(angle) * distance;
        const pupilY = Math.sin(angle) * distance;

        pupil.style.transform = `translate(calc(-50% + ${pupilX}px), calc(-50% + ${pupilY}px))`;
    });
}

function initForm() {
    const form = document.getElementById('analyzeForm');
    const urlInput = document.getElementById('urlInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const resultsSection = document.getElementById('resultsSection');
    const preloader = document.getElementById('preloader');
    const statusElement = document.getElementById('status');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const url = urlInput.value.trim();
        if (!url) return;

        // Show preloader
        preloader.classList.remove('hidden');
        statusElement.textContent = 'SCANNING...';
        statusElement.style.color = 'var(--primary-yellow)';
        
        // Disable button
        analyzeBtn.disabled = true;
        analyzeBtn.querySelector('.btn-text').textContent = 'SCANNING...';
        resultsSection.style.display = 'none';

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url }),
            });

            if (!response.ok) {
                const error = await response.json();
                alert(`ERROR: ${error.error}`);
                return;
            }

            const result = await response.json();
            displayResults(result);
            resultsSection.style.display = 'block';
            
            // Smooth scroll to results
            resultsSection.scrollIntoView({ behavior: 'smooth' });
            
            statusElement.textContent = 'SCAN COMPLETE';
            statusElement.style.color = 'var(--primary-green)';
        } catch (error) {
            alert(`ERROR: ${error.message}`);
            statusElement.textContent = 'SCAN FAILED';
            statusElement.style.color = 'var(--primary-red)';
        } finally {
            // Hide preloader
            preloader.classList.add('hidden');
            analyzeBtn.disabled = false;
            analyzeBtn.querySelector('.btn-text').textContent = 'INITIATE_SCAN';
        }
    });
}

function displayResults(result) {
    // Display score
    const scoreValue = document.getElementById('scoreValue');
    const scoreCircle = document.getElementById('scoreCircle');
    const ratingBadge = document.getElementById('ratingBadge');
    
    scoreValue.textContent = result.score;
    scoreCircle.style.borderColor = getScoreColor(result.score);
    scoreCircle.style.color = getScoreColor(result.score);
    scoreCircle.style.boxShadow = `0 0 15px ${getScoreColor(result.score)}`;
    
    ratingBadge.textContent = result.rating;
    ratingBadge.className = 'rating-badge bg-' + getScoreClass(result.score);

    // Display TLS info
    displayTLS(result.tls);

    // Display security headers
    displayHeaders(result.security_headers);

    // Display redirects
    displayRedirects(result.redirects);
}

function displayTLS(tls) {
    const tlsDetails = document.getElementById('tlsDetails');
    
    if (!tls) {
        tlsDetails.innerHTML = '<p>NO TLS DATA AVAILABLE</p>';
        return;
    }
    
    const versionClass = getTLSVersionClass(tls.version);
    const validClass = tls.valid ? 'status-pass' : 'status-fail';
    const weakCipher = isWeakCipher(tls.cipher_suite);

    tlsDetails.innerHTML = `
        <div class="tls-detail">
            <dt>TLS VERSION</dt>
            <dd class="${versionClass}">${tls.version || 'N/A'}</dd>
        </div>
        <div class="tls-detail">
            <dt>CIPHER SUITE</dt>
            <dd class="${weakCipher ? 'important-red' : ''}">${tls.cipher_suite || 'N/A'}</dd>
        </div>
        <div class="tls-detail">
            <dt>CERTIFICATE VALID</dt>
            <dd class="${validClass}">${tls.valid ? 'YES' : 'NO'}</dd>
        </div>
        <div class="tls-detail">
            <dt>SUBJECT</dt>
            <dd>${tls.subject || 'N/A'}</dd>
        </div>
        <div class="tls-detail">
            <dt>ISSUER</dt>
            <dd>${tls.issuer || 'N/A'}</dd>
        </div>
        <div class="tls-detail">
            <dt>EXPIRES</dt>
            <dd>${tls.expires_at || 'N/A'}</dd>
        </div>
    `;
}

function displayHeaders(headers) {
    const headersBody = document.getElementById('headersBody');
    
    if (!headers || headers.length === 0) {
        headersBody.innerHTML = '<tr><td colspan="4">NO HEADERS FOUND</td></tr>';
        return;
    }

    headersBody.innerHTML = headers.map(header => {
        const statusClass = `status-${header.status}`;
        const isImportant = header.status === 'fail' || (header.status === 'warn' && header.message);
        
        return `
            <tr>
                <td><strong>${escapeHtml(header.name)}</strong></td>
                <td><code>${escapeHtml(header.value) || 'MISSING'}</code></td>
                <td><span class="${statusClass}">${header.status.toUpperCase()}</span></td>
                <td class="${isImportant ? 'important-red' : ''}">${escapeHtml(header.message) || '-'}</td>
            </tr>
        `;
    }).join('');
}

function displayRedirects(redirects) {
    const redirectsList = document.getElementById('redirectsList');
    
    if (!redirects || redirects.length === 0) {
        redirectsList.innerHTML = '<p>NO REDIRECTS DETECTED</p>';
        return;
    }

    redirectsList.innerHTML = redirects.map((r, i) => `
        <div class="redirect-step ${i === redirects.length - 1 ? 'final' : ''}">
            <strong>STEP ${i + 1}:</strong> ${r.status_code} ${r.is_redirect ? '(REDIRECT)' : '(FINAL)'}
            ${r.location ? `<br><strong>LOCATION:</strong> ${escapeHtml(r.location)}` : ''}
        </div>
    `).join('');
}

function getScoreColor(score) {
    if (score >= 85) return '#00ff41';
    if (score >= 70) return '#f1c40f';
    return '#ff003c';
}

function getScoreClass(score) {
    if (score >= 85) return 'pass';
    if (score >= 70) return 'warn';
    return 'fail';
}

function getTLSVersionClass(version) {
    if (!version) return '';
    if (version.includes('TLS 1.3')) return 'status-pass';
    if (version.includes('TLS 1.2')) return 'status-pass';
    if (version.includes('TLS 1.1')) return 'status-warn';
    if (version.includes('TLS 1.0')) return 'status-fail';
    return '';
}

function isWeakCipher(cipher) {
    if (!cipher) return false;
    const weak = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon'];
    return weak.some(w => cipher.toUpperCase().includes(w));
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}