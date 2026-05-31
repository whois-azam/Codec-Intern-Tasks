/* ============================================================
   CipherCore — Cryptographic Tool Suite
   Frontend JavaScript Engine
   Pure Vanilla JS — Zero Dependencies
   ============================================================ */

const CipherCore = (() => {
    'use strict';

    // ─── Private State ──────────────────────────────────────────
    const state = {
        activeTab: 'encrypt',
        isProcessing: false,
        lastEncryptResult: null,
        animationQueue: [],
    };

    // ─── SVG Icon Templates ────────────────────────────────────
    const icons = {
        lock: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
        unlock: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>`,
        hash: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></svg>`,
        copy: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
        check: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
        x: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
        shield: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
        shieldCheck: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`,
        shieldX: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>`,
        activity: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
        key: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78zM15.5 7.5l2 2L21 6l-3-3-3.5 3.5"/></svg>`,
        arrowRight: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>`,
        file: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>`,
        info: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`,
        zap: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
    };

    // ─── DOM Element Cache ──────────────────────────────────────
    const dom = {};

    function cacheDom() {
        dom.tabBtns = document.querySelectorAll('.tab-btn');
        dom.tabPanels = document.querySelectorAll('.tab-panel');
        dom.encryptForm = document.getElementById('encrypt-form');
        dom.decryptForm = document.getElementById('decrypt-form');
        dom.hashTextForm = document.getElementById('hash-text-form');
        dom.btnEncrypt = document.getElementById('btn-encrypt');
        dom.btnDecrypt = document.getElementById('btn-decrypt');
        dom.btnHashText = document.getElementById('btn-hash-text');
        dom.encryptPlaintext = document.getElementById('encrypt-plaintext');
        dom.encryptPassword = document.getElementById('encrypt-password');
        dom.decryptCiphertext = document.getElementById('decrypt-ciphertext');
        dom.decryptIv = document.getElementById('decrypt-iv');
        dom.decryptSalt = document.getElementById('decrypt-salt');
        dom.decryptTag = document.getElementById('decrypt-tag');
        dom.decryptPassword = document.getElementById('decrypt-password');
        dom.hashTextInput = document.getElementById('hash-text-input');
        dom.fileDropZone = document.getElementById('file-drop-zone');
        dom.fileInput = document.getElementById('file-input');
        dom.pipelineContainer = document.getElementById('pipeline-container');
        dom.pipelineEmpty = document.getElementById('pipeline-empty');
        dom.pipelineStatus = document.getElementById('pipeline-status');
        dom.resultContainer = document.getElementById('result-container');
        dom.toastContainer = document.getElementById('toast-container');
    }

    // ─── API Layer ──────────────────────────────────────────────
    const api = {
        async encrypt(plaintext, password) {
            return await fetchJSON('/api/encrypt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ plaintext, password }),
            });
        },

        async decrypt(data) {
            return await fetchJSON('/api/decrypt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });
        },

        async hashText(text) {
            return await fetchJSON('/api/hash/text', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text }),
            });
        },

        async hashFile(file) {
            const formData = new FormData();
            formData.append('file', file);
            return await fetchJSON('/api/hash/file', {
                method: 'POST',
                body: formData,
            });
        },
    };

    async function fetchJSON(url, options) {
        try {
            const res = await fetch(url, options);
            const data = await res.json();
            if (!res.ok) {
                throw { status: res.status, ...data };
            }
            return data;
        } catch (err) {
            if (err.status) throw err;
            throw { status: 0, error: 'network_error', message: 'Network error — please check your connection.' };
        }
    }

    // ─── Tab System ─────────────────────────────────────────────
    function switchTab(tabName) {
        state.activeTab = tabName;

        dom.tabBtns.forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });

        dom.tabPanels.forEach(panel => {
            const isActive = panel.id === `panel-${tabName}`;
            panel.classList.toggle('active', isActive);
        });
    }

    // ─── Validation Helpers ─────────────────────────────────────
    function validateField(input, message) {
        const value = input.value.trim();
        if (!value) {
            input.classList.add('input-error');
            let errEl = input.parentElement.querySelector('.error-message');
            if (!errEl) {
                errEl = createElement('div', 'error-message');
                input.parentElement.appendChild(errEl);
            }
            errEl.textContent = message;
            errEl.classList.add('visible');
            return false;
        }
        clearFieldError(input);
        return true;
    }

    function clearFieldError(input) {
        input.classList.remove('input-error');
        const errEl = input.parentElement.querySelector('.error-message');
        if (errEl) errEl.classList.remove('visible');
    }

    function clearAllErrors(form) {
        form.querySelectorAll('.input-error').forEach(el => el.classList.remove('input-error'));
        form.querySelectorAll('.error-message.visible').forEach(el => el.classList.remove('visible'));
    }

    // ─── Button Loading State ───────────────────────────────────
    function setButtonLoading(btn, loading) {
        if (loading) {
            btn.disabled = true;
            btn.classList.add('btn-loading');
            if (!btn.querySelector('.btn-spinner')) {
                const spinner = createElement('span', 'btn-spinner');
                btn.appendChild(spinner);
            }
        } else {
            btn.disabled = false;
            btn.classList.remove('btn-loading');
            const spinner = btn.querySelector('.btn-spinner');
            if (spinner) spinner.remove();
        }
    }

    // ─── Encryption Handler ─────────────────────────────────────
    async function handleEncrypt(e) {
        e.preventDefault();
        if (state.isProcessing) return;

        clearAllErrors(dom.encryptForm);
        const v1 = validateField(dom.encryptPlaintext, 'Plaintext message is required');
        const v2 = validateField(dom.encryptPassword, 'Security passphrase is required');
        if (!v1 || !v2) return;

        state.isProcessing = true;
        setButtonLoading(dom.btnEncrypt, true);
        clearPipeline();
        updatePipelineStatus('Encrypting...');

        try {
            const response = await api.encrypt(
                dom.encryptPlaintext.value.trim(),
                dom.encryptPassword.value
            );

            const data = response.data || response;

            // Animate pipeline steps
            if (data.pipeline && data.pipeline.length > 0) {
                await animatePipeline(data.pipeline, dom.pipelineContainer);
            }

            // Show result card
            showEncryptResult(data);
            state.lastEncryptResult = data;
            updatePipelineStatus('Encryption complete');
            showNotification('Encryption successful!', 'success');
        } catch (err) {
            updatePipelineStatus('Encryption failed');
            showNotification(err.message || 'Encryption failed', 'error');
        } finally {
            state.isProcessing = false;
            setButtonLoading(dom.btnEncrypt, false);
        }
    }

    function showEncryptResult(data) {
        dom.resultContainer.style.display = 'block';
        dom.resultContainer.innerHTML = '';

        const card = createElement('div', 'result-card success');
        const fields = [
            { label: 'Ciphertext', value: data.ciphertext },
            { label: 'IV', value: data.iv },
            { label: 'Salt', value: data.salt },
            { label: 'Tag', value: data.tag },
        ];

        fields.forEach(f => {
            if (f.value) {
                card.appendChild(createResultField(f.label, f.value));
            }
        });

        // Test Decrypt button
        const testBtn = createElement('button', 'btn-secondary test-decrypt-btn');
        testBtn.innerHTML = `${icons.arrowRight} <span>Test Decrypt →</span>`;
        testBtn.addEventListener('click', () => autoFillDecrypt(data));
        card.appendChild(testBtn);

        dom.resultContainer.appendChild(card);
    }

    function createResultField(label, value) {
        const field = createElement('div', 'result-field');

        const labelEl = createElement('span', 'result-label');
        labelEl.textContent = label;

        const valueEl = createElement('span', 'result-value');
        valueEl.textContent = value;

        const copyBtn = createElement('button', 'copy-btn');
        copyBtn.innerHTML = icons.copy;
        copyBtn.title = `Copy ${label}`;
        copyBtn.addEventListener('click', () => copyToClipboard(value, copyBtn));

        field.appendChild(labelEl);
        field.appendChild(valueEl);
        field.appendChild(copyBtn);
        return field;
    }

    // ─── Decryption Handler ─────────────────────────────────────
    async function handleDecrypt(e) {
        e.preventDefault();
        if (state.isProcessing) return;

        clearAllErrors(dom.decryptForm);
        const validations = [
            validateField(dom.decryptCiphertext, 'Ciphertext is required'),
            validateField(dom.decryptIv, 'IV is required'),
            validateField(dom.decryptSalt, 'Salt is required'),
            validateField(dom.decryptTag, 'Authentication tag is required'),
            validateField(dom.decryptPassword, 'Passphrase is required'),
        ];
        if (validations.includes(false)) return;

        state.isProcessing = true;
        setButtonLoading(dom.btnDecrypt, true);
        clearPipeline();
        updatePipelineStatus('Decrypting...');

        try {
            const response = await api.decrypt({
                ciphertext: dom.decryptCiphertext.value.trim(),
                iv: dom.decryptIv.value.trim(),
                salt: dom.decryptSalt.value.trim(),
                tag: dom.decryptTag.value.trim(),
                password: dom.decryptPassword.value,
            });

            const data = response.data || response;

            // Animate pipeline
            if (data.pipeline && data.pipeline.length > 0) {
                await animatePipeline(data.pipeline, dom.pipelineContainer);
            }

            // Show seal intact + result
            showDecryptSuccess(data);
            updatePipelineStatus('Decryption verified');
            showNotification('Decryption & verification successful!', 'success');
        } catch (err) {
            const isTagMismatch = err.error === 'tag_mismatch' || err.error === 'decryption_failed';

            if (err.data && err.data.pipeline) {
                await animatePipeline(err.data.pipeline, dom.pipelineContainer);
            }

            showDecryptFailure(err.message || 'Authentication failed', isTagMismatch);
            updatePipelineStatus('Verification failed');
            showNotification(err.message || 'Decryption failed', 'error');
        } finally {
            state.isProcessing = false;
            setButtonLoading(dom.btnDecrypt, false);
        }
    }

    function showDecryptSuccess(data) {
        dom.resultContainer.style.display = 'block';
        dom.resultContainer.innerHTML = '';

        // Seal intact animation
        const sealContainer = createElement('div', 'seal-container');
        const sealIntact = createElement('div', 'seal-intact');
        sealIntact.innerHTML = `
            ${icons.shieldCheck}
            <span class="seal-label">Seal Intact</span>
        `;
        sealContainer.appendChild(sealIntact);

        // Decrypted plaintext
        const card = createElement('div', 'result-card success');
        card.appendChild(sealContainer);

        const plaintextField = createElement('div', 'result-field');
        const ptLabel = createElement('span', 'result-label');
        ptLabel.textContent = 'Plaintext';
        const ptValue = createElement('span', 'result-value');
        ptValue.style.color = 'var(--accent-green)';

        const copyBtn = createElement('button', 'copy-btn');
        copyBtn.innerHTML = icons.copy;
        copyBtn.addEventListener('click', () => copyToClipboard(data.plaintext, copyBtn));

        plaintextField.appendChild(ptLabel);
        plaintextField.appendChild(ptValue);
        plaintextField.appendChild(copyBtn);
        card.appendChild(plaintextField);
        dom.resultContainer.appendChild(card);

        // Typewriter effect for plaintext
        typewriterEffect(ptValue, data.plaintext, 30);
    }

    function showDecryptFailure(message, isTagMismatch) {
        dom.resultContainer.style.display = 'block';
        dom.resultContainer.innerHTML = '';

        const sealContainer = createElement('div', 'seal-container');
        const sealBroken = createElement('div', 'seal-broken');
        sealBroken.innerHTML = `
            ${icons.shieldX}
            <span class="seal-label">${isTagMismatch ? 'Seal Broken — Authentication Failed' : 'Decryption Failed'}</span>
        `;
        sealContainer.appendChild(sealBroken);

        const card = createElement('div', 'result-card error');
        card.appendChild(sealContainer);

        const errorMsg = createElement('p', 'text-center');
        errorMsg.style.cssText = 'color: var(--accent-red); font-size: 0.85rem; margin-top: var(--space-md);';
        errorMsg.textContent = message;
        card.appendChild(errorMsg);

        dom.resultContainer.appendChild(card);
    }

    // ─── Auto-Fill Decrypt ──────────────────────────────────────
    function autoFillDecrypt(data) {
        dom.decryptCiphertext.value = data.ciphertext || '';
        dom.decryptIv.value = data.iv || '';
        dom.decryptSalt.value = data.salt || '';
        dom.decryptTag.value = data.tag || '';
        dom.decryptPassword.value = '';
        switchTab('decrypt');
        dom.decryptPassword.focus();
        showNotification('Encryption output auto-filled. Enter your passphrase to decrypt.', 'info');
    }

    // ─── Hash Text Handler ──────────────────────────────────────
    async function handleHashText(e) {
        e.preventDefault();
        if (state.isProcessing) return;

        clearAllErrors(dom.hashTextForm);
        if (!validateField(dom.hashTextInput, 'Text input is required')) return;

        state.isProcessing = true;
        setButtonLoading(dom.btnHashText, true);
        clearPipeline();
        updatePipelineStatus('Hashing text...');

        try {
            const response = await api.hashText(dom.hashTextInput.value);
            const data = response.data || response;

            if (data.pipeline && data.pipeline.length > 0) {
                await animatePipeline(data.pipeline, dom.pipelineContainer);
            }

            showHashResult(data);
            updatePipelineStatus('Hash generated');
            showNotification('Hash generated successfully!', 'success');
        } catch (err) {
            updatePipelineStatus('Hashing failed');
            showNotification(err.message || 'Hashing failed', 'error');
        } finally {
            state.isProcessing = false;
            setButtonLoading(dom.btnHashText, false);
        }
    }

    function showHashResult(data) {
        dom.resultContainer.style.display = 'block';
        dom.resultContainer.innerHTML = '';

        const card = createElement('div', 'result-card success');

        // Hash value with character reveal
        const hashDisplay = createElement('div', 'hash-result');
        const hashStr = data.hash || data.digest || '';
        hashDisplay.innerHTML = '';
        card.appendChild(hashDisplay);

        // Copy button for hash
        const copyRow = createElement('div', 'result-field');
        copyRow.style.justifyContent = 'flex-end';
        copyRow.style.borderBottom = 'none';
        const copyBtn = createElement('button', 'copy-btn');
        copyBtn.innerHTML = icons.copy;
        copyBtn.title = 'Copy hash';
        copyBtn.addEventListener('click', () => copyToClipboard(hashStr, copyBtn));
        copyRow.appendChild(copyBtn);
        card.appendChild(copyRow);

        // Hash metadata
        const meta = createElement('div', 'hash-meta');
        const metaItems = [
            { label: 'Algorithm', value: data.algorithm || 'SHA-256' },
            { label: 'Input length', value: `${data.input_length || dom.hashTextInput.value.length} chars` },
            { label: 'Hash bits', value: data.hash_bits || '256' },
        ];
        metaItems.forEach(item => {
            const metaEl = createElement('div', 'hash-meta-item');
            metaEl.innerHTML = `${item.label}: <span>${item.value}</span>`;
            meta.appendChild(metaEl);
        });
        card.appendChild(meta);

        dom.resultContainer.appendChild(card);

        // Animate character-by-character reveal
        charRevealEffect(hashDisplay, hashStr, 25);
    }

    // ─── File Drop Handler ──────────────────────────────────────
    function setupFileDropZone() {
        const dropZone = dom.fileDropZone;
        if (!dropZone) return;

        ['dragenter', 'dragover'].forEach(evt => {
            dropZone.addEventListener(evt, e => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(evt => {
            dropZone.addEventListener(evt, e => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.remove('dragover');
            });
        });

        dropZone.addEventListener('drop', e => {
            const files = e.dataTransfer.files;
            if (files.length > 0) processFile(files[0]);
        });

        dropZone.addEventListener('click', () => {
            dom.fileInput.click();
        });

        dom.fileInput.addEventListener('change', () => {
            if (dom.fileInput.files.length > 0) {
                processFile(dom.fileInput.files[0]);
            }
        });
    }

    async function processFile(file) {
        const dropZone = dom.fileDropZone;
        dropZone.classList.add('processing');
        clearPipeline();
        updatePipelineStatus('Hashing file...');

        // Show file info
        const content = dropZone.querySelector('.drop-zone-content');
        content.innerHTML = `
            <div class="drop-zone-icon">${icons.file}</div>
            <p class="drop-zone-title file-info-name">${file.name}</p>
            <p class="drop-zone-subtitle">${formatBytes(file.size)} • ${file.type || 'unknown type'}</p>
        `;

        try {
            const response = await api.hashFile(file);
            const data = response.data || response;

            if (data.pipeline && data.pipeline.length > 0) {
                await animatePipeline(data.pipeline, dom.pipelineContainer);
            }

            showFileHashResult(data, file);
            updatePipelineStatus('File hash generated');
            showNotification('File hash generated!', 'success');
        } catch (err) {
            updatePipelineStatus('File hashing failed');
            showNotification(err.message || 'File hashing failed', 'error');
        } finally {
            dropZone.classList.remove('processing');
            // Reset drop zone content after a delay
            setTimeout(() => {
                content.innerHTML = `
                    <div class="drop-zone-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
                    </div>
                    <p class="drop-zone-title">Drag & drop a file here</p>
                    <p class="drop-zone-subtitle">or click to select</p>
                `;
            }, 5000);
        }
    }

    function showFileHashResult(data, file) {
        dom.resultContainer.style.display = 'block';
        dom.resultContainer.innerHTML = '';

        const card = createElement('div', 'result-card success');

        // File info
        const fileInfo = createElement('div', 'file-info');
        fileInfo.innerHTML = `
            ${icons.file}
            <div>
                <span class="file-info-name">${file.name}</span> —
                ${formatBytes(file.size)} • ${file.type || 'unknown'}
            </div>
        `;
        card.appendChild(fileInfo);

        // Hash display
        const hashDisplay = createElement('div', 'hash-result');
        const hashStr = data.hash || data.digest || '';
        card.appendChild(hashDisplay);

        // Copy button
        const copyRow = createElement('div', 'result-field');
        copyRow.style.justifyContent = 'flex-end';
        copyRow.style.borderBottom = 'none';
        const copyBtn = createElement('button', 'copy-btn');
        copyBtn.innerHTML = icons.copy;
        copyBtn.addEventListener('click', () => copyToClipboard(hashStr, copyBtn));
        copyRow.appendChild(copyBtn);
        card.appendChild(copyRow);

        // Meta
        const meta = createElement('div', 'hash-meta');
        const items = [
            { label: 'Algorithm', value: data.algorithm || 'SHA-256' },
            { label: 'File size', value: formatBytes(file.size) },
            { label: 'Hash bits', value: data.hash_bits || '256' },
        ];
        items.forEach(item => {
            const el = createElement('div', 'hash-meta-item');
            el.innerHTML = `${item.label}: <span>${item.value}</span>`;
            meta.appendChild(el);
        });
        card.appendChild(meta);
        dom.resultContainer.appendChild(card);

        charRevealEffect(hashDisplay, hashStr, 25);
    }

    // ─── Pipeline Animation Engine ─────────────────────────────
    function clearPipeline() {
        dom.pipelineContainer.innerHTML = '';
        dom.resultContainer.style.display = 'none';
        dom.resultContainer.innerHTML = '';
        if (dom.pipelineEmpty) {
            dom.pipelineContainer.appendChild(dom.pipelineEmpty);
            dom.pipelineEmpty.style.display = 'none';
        }
    }

    function updatePipelineStatus(text) {
        if (dom.pipelineStatus) {
            dom.pipelineStatus.textContent = text;
        }
    }

    async function animatePipeline(steps, container) {
        // Hide empty state
        const emptyState = container.querySelector('.pipeline-empty-state');
        if (emptyState) emptyState.style.display = 'none';

        for (let i = 0; i < steps.length; i++) {
            const step = steps[i];

            // Create step element
            const stepEl = createPipelineStep(step, i);
            container.appendChild(stepEl);

            // Animate step appearing
            await delay(100);
            stepEl.classList.add('active');

            // Show value with typewriter if present
            const valueEl = stepEl.querySelector('.pipeline-value');
            if (valueEl && step.value) {
                await typewriterEffectAsync(valueEl, step.value, 12);
            }

            await delay(300);

            // Mark as completed
            stepEl.classList.remove('active');
            stepEl.classList.add('completed');

            // Update the step icon to checkmark
            const iconEl = stepEl.querySelector('.step-icon');
            if (iconEl) iconEl.innerHTML = icons.check;

            // Add connector to next step (except last)
            if (i < steps.length - 1) {
                const connector = createElement('div', 'pipeline-connector');
                container.appendChild(connector);

                // Add flowing particle
                const particle = createElement('div', 'data-flow-particle');
                connector.appendChild(particle);

                await delay(400);
                particle.remove();
            }
        }
    }

    function createPipelineStep(step, index) {
        const stepEl = createElement('div', 'pipeline-step');
        stepEl.style.animationDelay = `${index * 0.1}s`;

        const stepIcon = getStepIcon(step.step || step.name || '');

        stepEl.innerHTML = `
            <div class="step-header">
                <span class="step-icon">${stepIcon}</span>
                <span class="step-label">${step.step || step.name || `Step ${index + 1}`}</span>
            </div>
            <div class="step-description">${step.description || ''}</div>
            ${step.value ? `<div class="pipeline-value" title="Click to expand">${truncateMiddle(step.value, 50)}</div>` : ''}
        `;

        // Expand/collapse value on click
        const valueEl = stepEl.querySelector('.pipeline-value');
        if (valueEl) {
            valueEl.addEventListener('click', () => {
                valueEl.classList.toggle('expanded');
                valueEl.textContent = valueEl.classList.contains('expanded')
                    ? step.value
                    : truncateMiddle(step.value, 50);
            });
        }

        return stepEl;
    }

    function getStepIcon(stepName) {
        const name = stepName.toLowerCase();
        if (name.includes('key') || name.includes('pbkdf') || name.includes('deriv')) return icons.key;
        if (name.includes('encrypt') || name.includes('aes') || name.includes('cipher')) return icons.lock;
        if (name.includes('decrypt')) return icons.unlock;
        if (name.includes('hash') || name.includes('sha') || name.includes('digest')) return icons.hash;
        if (name.includes('salt') || name.includes('random') || name.includes('iv') || name.includes('nonce')) return icons.zap;
        if (name.includes('tag') || name.includes('auth') || name.includes('verif') || name.includes('seal')) return icons.shield;
        if (name.includes('encode') || name.includes('base64')) return icons.activity;
        return icons.activity;
    }

    // ─── Text Animation Effects ─────────────────────────────────
    function charRevealEffect(container, text, delayMs) {
        container.innerHTML = '';
        const chars = text.split('');
        chars.forEach((char, i) => {
            const span = document.createElement('span');
            span.className = 'hash-char';
            span.textContent = char;
            span.style.animationDelay = `${i * delayMs}ms`;
            container.appendChild(span);
        });
    }

    function typewriterEffect(element, text, delayMs) {
        element.textContent = '';
        let i = 0;
        function type() {
            if (i < text.length) {
                element.textContent += text.charAt(i);
                i++;
                setTimeout(type, delayMs);
            }
        }
        type();
    }

    function typewriterEffectAsync(element, text, delayMs) {
        return new Promise(resolve => {
            const display = truncateMiddle(text, 60);
            element.textContent = '';
            let i = 0;
            function type() {
                if (i < display.length) {
                    element.textContent += display.charAt(i);
                    i++;
                    setTimeout(type, delayMs);
                } else {
                    resolve();
                }
            }
            type();
        });
    }

    // ─── Copy to Clipboard ──────────────────────────────────────
    async function copyToClipboard(text, buttonElement) {
        try {
            await navigator.clipboard.writeText(text);
            buttonElement.innerHTML = icons.check;
            buttonElement.classList.add('copied');
            showNotification('Copied to clipboard!', 'info');
            setTimeout(() => {
                buttonElement.innerHTML = icons.copy;
                buttonElement.classList.remove('copied');
            }, 2000);
        } catch (err) {
            // Fallback
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            buttonElement.innerHTML = icons.check;
            buttonElement.classList.add('copied');
            setTimeout(() => {
                buttonElement.innerHTML = icons.copy;
                buttonElement.classList.remove('copied');
            }, 2000);
        }
    }

    // ─── Toast Notification System ──────────────────────────────
    function showNotification(message, type = 'info') {
        const iconMap = {
            success: icons.check,
            error: icons.x,
            info: icons.info,
        };

        const toast = createElement('div', `toast toast--${type}`);
        toast.innerHTML = `${iconMap[type] || iconMap.info}<span>${message}</span>`;

        dom.toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('toast-exit');
            toast.addEventListener('animationend', () => toast.remove());
        }, 4000);
    }

    // ─── Utility Functions ──────────────────────────────────────
    function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function truncateMiddle(str, maxLen) {
        if (!str || str.length <= maxLen) return str || '';
        const half = Math.floor((maxLen - 3) / 2);
        return str.slice(0, half) + '...' + str.slice(-half);
    }

    function createElement(tag, className) {
        const el = document.createElement(tag);
        if (className) el.className = className;
        return el;
    }

    function delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // ─── Password Toggle ────────────────────────────────────────
    function setupPasswordToggles() {
        document.querySelectorAll('.password-toggle').forEach(btn => {
            btn.addEventListener('click', () => {
                const input = btn.parentElement.querySelector('input');
                if (!input) return;
                const isPassword = input.type === 'password';
                input.type = isPassword ? 'text' : 'password';
                btn.innerHTML = isPassword
                    ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`
                    : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
            });
        });
    }

    // ─── Background Particle Effects ────────────────────────────
    function initBackgroundParticles() {
        const canvas = document.createElement('canvas');
        canvas.id = 'particle-canvas';
        canvas.style.cssText = 'position:fixed;inset:0;z-index:0;pointer-events:none;opacity:0.4;';
        document.body.insertBefore(canvas, document.body.firstChild);

        const ctx = canvas.getContext('2d');
        let particles = [];
        let animFrameId;
        const PARTICLE_COUNT = 35;

        function resize() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        }

        function createParticle() {
            return {
                x: Math.random() * canvas.width,
                y: Math.random() * canvas.height,
                vx: (Math.random() - 0.5) * 0.3,
                vy: (Math.random() - 0.5) * 0.3,
                radius: Math.random() * 1.5 + 0.5,
                opacity: Math.random() * 0.5 + 0.1,
                color: Math.random() > 0.5 ? '0, 229, 255' : '124, 77, 255',
            };
        }

        function initParticles() {
            particles = [];
            for (let i = 0; i < PARTICLE_COUNT; i++) {
                particles.push(createParticle());
            }
        }

        function drawParticles() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            for (let i = 0; i < particles.length; i++) {
                const p = particles[i];
                p.x += p.vx;
                p.y += p.vy;

                // Wrap around
                if (p.x < 0) p.x = canvas.width;
                if (p.x > canvas.width) p.x = 0;
                if (p.y < 0) p.y = canvas.height;
                if (p.y > canvas.height) p.y = 0;

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(${p.color}, ${p.opacity})`;
                ctx.fill();

                // Draw connections
                for (let j = i + 1; j < particles.length; j++) {
                    const p2 = particles[j];
                    const dx = p.x - p2.x;
                    const dy = p.y - p2.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 150) {
                        ctx.beginPath();
                        ctx.moveTo(p.x, p.y);
                        ctx.lineTo(p2.x, p2.y);
                        ctx.strokeStyle = `rgba(0, 229, 255, ${0.06 * (1 - dist / 150)})`;
                        ctx.lineWidth = 0.5;
                        ctx.stroke();
                    }
                }
            }

            animFrameId = requestAnimationFrame(drawParticles);
        }

        resize();
        initParticles();
        drawParticles();

        window.addEventListener('resize', () => {
            resize();
        });

        // Cleanup on page hide
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                cancelAnimationFrame(animFrameId);
            } else {
                drawParticles();
            }
        });
    }

    // ─── Input Clear on Focus ───────────────────────────────────
    function setupInputClearOnFocus() {
        document.querySelectorAll('.crypto-input, .crypto-textarea').forEach(input => {
            input.addEventListener('focus', () => clearFieldError(input));
        });
    }

    // ─── Initialization ─────────────────────────────────────────
    function init() {
        cacheDom();

        // Tab click listeners
        dom.tabBtns.forEach(btn => {
            btn.addEventListener('click', () => switchTab(btn.dataset.tab));
        });

        // Form submit handlers
        if (dom.encryptForm) {
            dom.encryptForm.addEventListener('submit', handleEncrypt);
        }
        if (dom.decryptForm) {
            dom.decryptForm.addEventListener('submit', handleDecrypt);
        }
        if (dom.hashTextForm) {
            dom.hashTextForm.addEventListener('submit', handleHashText);
        }

        // File drop zone
        setupFileDropZone();

        // Password toggles
        setupPasswordToggles();

        // Clear errors on focus
        setupInputClearOnFocus();

        // Background particles
        initBackgroundParticles();

        // Set default tab
        switchTab('encrypt');

        console.log(
            '%c🛡️ CipherCore %cv1.0 %c— Cryptographic Tool Suite',
            'color: #00e5ff; font-weight: bold; font-size: 14px;',
            'color: #7c4dff; font-weight: bold; font-size: 14px;',
            'color: #94a3b8; font-size: 12px;'
        );
    }

    // ─── Public API ─────────────────────────────────────────────
    return {
        init,
        switchTab,
        getState: () => ({ ...state }),
    };
})();

// ─── Bootstrap ──────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    CipherCore.init();
});
