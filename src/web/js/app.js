/**
 * Splunk Agent Web UI
 * ===================
 * 
 * Main application logic for the web interface.
 */

// =============================================================================
// STATE
// =============================================================================

const state = {
    currentView: 'chat',
    inputMode: 'text',
    isLoading: false,
    status: null,
    config: null,
    showReasoning: true,
    // Session token tracking
    sessionTokens: {
        total: 0,
        input: 0,
        output: 0,
    },
};

// =============================================================================
// DOM ELEMENTS
// =============================================================================

const elements = {
    // Navigation
    navItems: document.querySelectorAll('.nav-item'),
    views: document.querySelectorAll('.view'),
    
    // Status
    statusLLM: document.getElementById('status-llm'),
    statusSplunk: document.getElementById('status-splunk'),
    statusDocs: document.getElementById('status-docs'),
    statusDetections: document.getElementById('status-detections'),
    statusCIM: document.getElementById('status-cim'),
    statusAttack: document.getElementById('status-attack'),
    tokenCount: document.getElementById('token-count'),
    
    // Chat
    chatMessages: document.getElementById('chat-messages'),
    userInput: document.getElementById('user-input'),
    sendBtn: document.getElementById('send-btn'),
    modeButtons: document.querySelectorAll('.mode-btn'),
    inputText: document.getElementById('input-text'),
    inputIOC: document.getElementById('input-ioc'),
    iocUrl: document.getElementById('ioc-url'),
    iocFile: document.getElementById('ioc-file'),
    sendIOCBtn: document.getElementById('send-ioc-btn'),
    inputE2E: document.getElementById('input-e2e'),
    e2eUrl: document.getElementById('e2e-url'),
    e2eFile: document.getElementById('e2e-file'),
    e2eValidateSplunk: document.getElementById('e2e-validate-splunk'),
    e2eTestAttack: document.getElementById('e2e-test-attack'),
    sendE2EBtn: document.getElementById('send-e2e-btn'),
    showReasoningToggle: document.getElementById('show-reasoning'),
    
    // Search
    searchQuery: document.getElementById('search-query'),
    searchRagType: document.getElementById('search-rag-type'),
    searchBtn: document.getElementById('search-btn'),
    searchResults: document.getElementById('search-results'),
    
    // Settings
    llmProvider: document.getElementById('llm-provider'),
    llmApiKey: document.getElementById('llm-api-key'),
    llmModel: document.getElementById('llm-model'),
    splunkHost: document.getElementById('splunk-host'),
    splunkPort: document.getElementById('splunk-port'),
    splunkToken: document.getElementById('splunk-token'),
    splunkVerifySSL: document.getElementById('splunk-verify-ssl'),
    testSplunkBtn: document.getElementById('test-splunk-btn'),
    splunkTestResult: document.getElementById('splunk-test-result'),
    saveConfigBtn: document.getElementById('save-config-btn'),
};

// =============================================================================
// NAVIGATION
// =============================================================================

function switchView(viewName) {
    state.currentView = viewName;
    
    // Update nav items
    elements.navItems.forEach(item => {
        item.classList.toggle('active', item.dataset.view === viewName);
    });
    
    // Update views
    elements.views.forEach(view => {
        view.classList.toggle('active', view.id === `view-${viewName}`);
    });
    
    // Load view-specific data
    if (viewName === 'settings') {
        loadConfig();
    }
}

// =============================================================================
// STATUS
// =============================================================================

async function updateStatus() {
    try {
        const status = await window.api.status();
        state.status = status;
        
        // Update LLM status
        const llmDot = elements.statusLLM.querySelector('.status-dot');
        const llmValue = elements.statusLLM.querySelector('.status-value');
        if (status.llm_provider) {
            llmDot.classList.add('connected');
            llmValue.textContent = status.llm_provider.split('/')[0];
        } else {
            llmDot.classList.remove('connected');
            llmValue.textContent = 'Not configured';
        }
        
        // Update Splunk status
        const splunkDot = elements.statusSplunk.querySelector('.status-dot');
        const splunkValue = elements.statusSplunk.querySelector('.status-value');
        if (status.splunk_connected) {
            splunkDot.classList.add('connected');
            splunkValue.textContent = 'Connected';
        } else {
            splunkDot.classList.remove('connected');
            splunkValue.textContent = 'Disconnected';
        }
        
        // Update RAG statuses
        const docsDot = elements.statusDocs.querySelector('.status-dot');
        const docsValue = elements.statusDocs.querySelector('.status-value');
        docsValue.textContent = `${status.doc_rag_documents || 0} docs`;
        docsDot.classList.toggle('connected', status.doc_rag_documents > 0);
        
        const detDot = elements.statusDetections.querySelector('.status-dot');
        const detValue = elements.statusDetections.querySelector('.status-value');
        detValue.textContent = `${status.detection_rag_documents || 0} rules`;
        detDot.classList.toggle('connected', status.detection_rag_documents > 0);
        
        // Update CIM RAG status
        if (elements.statusCIM) {
            const cimDot = elements.statusCIM.querySelector('.status-dot');
            const cimValue = elements.statusCIM.querySelector('.status-value');
            cimValue.textContent = `${status.cim_rag_documents || 0} docs`;
            cimDot.classList.toggle('connected', status.cim_rag_documents > 0);
        }
        
        // Update Attack Data RAG status
        if (elements.statusAttack) {
            const attackDot = elements.statusAttack.querySelector('.status-dot');
            const attackValue = elements.statusAttack.querySelector('.status-value');
            attackValue.textContent = `${status.attack_data_documents || 0} sets`;
            attackDot.classList.toggle('connected', status.attack_data_documents > 0);
        }
        
        // Update session token display (NOT from server - we track locally)
        if (elements.tokenCount) {
            elements.tokenCount.textContent = state.sessionTokens.total.toLocaleString();
            // Add tooltip with breakdown
            elements.tokenCount.title = `Input: ${state.sessionTokens.input.toLocaleString()} | Output: ${state.sessionTokens.output.toLocaleString()}`;
            // Add warning class if approaching common limits
            if (state.sessionTokens.total > 80000) {
                elements.tokenCount.classList.add('warning');
            } else {
                elements.tokenCount.classList.remove('warning');
            }
        }
        
    } catch (error) {
        console.error('Failed to update status:', error);
    }
}

// =============================================================================
// CHAT
// =============================================================================

function switchInputMode(mode) {
    state.inputMode = mode;
    
    elements.modeButtons.forEach(btn => {
        btn.classList.toggle('active', btn.dataset.mode === mode);
    });
    
    elements.inputText.classList.toggle('hidden', mode !== 'text');
    elements.inputIOC.classList.toggle('hidden', mode !== 'ioc');
    if (elements.inputE2E) {
        elements.inputE2E.classList.toggle('hidden', mode !== 'e2e');
    }
}

function addMessage(type, content) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    
    const avatar = type === 'user' ? '👤' : '🤖';
    
    messageDiv.innerHTML = `
        <div class="message-avatar">${avatar}</div>
        <div class="message-content">${content}</div>
    `;
    
    elements.chatMessages.appendChild(messageDiv);
    elements.chatMessages.scrollTop = elements.chatMessages.scrollHeight;
    
    return messageDiv;
}

function addLoadingMessage() {
    const showReasoning = elements.showReasoningToggle?.checked ?? true;
    
    if (showReasoning) {
        return addMessage('assistant', `
            <div class="loading">
                <span>Processing with Chain of Thought</span>
                <div class="loading-dots">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
            </div>
            <div class="processing-indicator">
                <div class="processing-step" style="--step-index: 0">
                    <span class="status-icon">🔄</span>
                    <span class="step-text">Analyzing input...</span>
                </div>
                <div class="processing-step" style="--step-index: 1">
                    <span class="status-icon">🔄</span>
                    <span class="step-text">Querying knowledge bases</span>
                </div>
                <div class="processing-step" style="--step-index: 2">
                    <span class="status-icon">🔄</span>
                    <span class="step-text">Building context</span>
                </div>
                <div class="processing-step" style="--step-index: 3">
                    <span class="status-icon">🔄</span>
                    <span class="step-text">Generating SPL query</span>
                </div>
                <div class="processing-step" style="--step-index: 4">
                    <span class="status-icon">🔄</span>
                    <span class="step-text">Validating against Splunk</span>
                </div>
            </div>
        `);
    }
    
    return addMessage('assistant', `
        <div class="loading">
            <span>Generating query</span>
            <div class="loading-dots">
                <span></span>
                <span></span>
                <span></span>
            </div>
        </div>
    `);
}

function formatQueryResult(result) {
    const statusClass = result.status === 'success' ? 'success' : 'warning';
    const statusIcon = result.status === 'success' ? '✓' : '⚠';
    
    // Store the query in a unique ID for copy functionality
    const queryId = 'query-' + Date.now();
    window._queryCache = window._queryCache || {};
    window._queryCache[queryId] = result.spl_query || '';
    
    let html = `
        <div class="query-result">
            <div class="spl-code">
                <button class="copy-btn" data-query-id="${queryId}" onclick="copyQueryById(this)">Copy</button>
                <pre>${escapeHtml(result.spl_query || 'No query generated')}</pre>
            </div>
            
            <p><strong>Explanation:</strong></p>
            <p>${escapeHtml(result.explanation)}</p>
            
            <div class="result-meta">
                <div class="result-meta-item ${statusClass}">
                    <span>Status:</span>
                    <span class="value">${statusIcon} ${result.status}</span>
                </div>
                <div class="result-meta-item">
                    <span>Input:</span>
                    <span class="value">${result.input_type}</span>
                </div>
                <div class="result-meta-item">
                    <span>Time:</span>
                    <span class="value">${result.total_time.toFixed(2)}s</span>
                </div>
                ${result.validated ? `
                <div class="result-meta-item success">
                    <span>Validated:</span>
                    <span class="value">${result.result_count} results</span>
                </div>
                ` : ''}
                ${result.confidence_score ? `
                <div class="result-meta-item">
                    <span>Confidence:</span>
                    <span class="value">${(result.confidence_score * 100).toFixed(0)}%</span>
                </div>
                ` : ''}
            </div>
    `;
    
    // Add reasoning panel if available
    if (result.reasoning && result.reasoning.steps && result.reasoning.steps.length > 0) {
        html += formatReasoningPanel(result.reasoning, result.confidence_score);
    }
    
    if (result.ioc_summary) {
        html += `
            <p style="margin-top: 16px;"><strong>IOC Summary:</strong></p>
            <pre style="font-size: 12px; color: var(--text-secondary);">${escapeHtml(result.ioc_summary)}</pre>
        `;
    }
    
    if (result.warnings && result.warnings.length > 0) {
        html += `
            <p style="margin-top: 16px; color: var(--accent-warning);"><strong>Warnings:</strong></p>
            <ul>
                ${result.warnings.map(w => `<li>${escapeHtml(w)}</li>`).join('')}
            </ul>
        `;
    }
    
    html += '</div>';
    return html;
}

function formatReasoningPanel(reasoning, confidenceScore) {
    const confidence = confidenceScore || 0.5;
    const confidencePercent = (confidence * 100).toFixed(0);
    
    let stepsHtml = reasoning.steps.map(step => formatReasoningStep(step)).join('');
    
    return `
        <div class="reasoning-panel" onclick="toggleReasoningPanel(this)">
            <div class="reasoning-header">
                <div class="reasoning-title">
                    <span class="icon">🔍</span>
                    <span>Chain of Thought</span>
                </div>
                <div class="confidence-badge">
                    <span>Confidence:</span>
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: ${confidencePercent}%"></div>
                    </div>
                    <span>${confidencePercent}%</span>
                </div>
                <span class="reasoning-expand">▼</span>
            </div>
            <div class="reasoning-body">
                <div class="reasoning-steps">
                    ${stepsHtml}
                </div>
            </div>
        </div>
    `;
}

function formatReasoningStep(step) {
    const statusIcons = {
        'complete': '✓',
        'in_progress': '🔄',
        'error': '✗',
        'pending': '○'
    };
    
    const icon = statusIcons[step.status] || '•';
    let detailsHtml = '';
    
    // Format details based on step type
    if (step.step_type === 'input_classification') {
        if (step.details.input_type) {
            detailsHtml += `<div class="step-detail-item">Type: ${step.details.input_type}</div>`;
        }
    } else if (step.step_type === 'rag_retrieval' && step.details.rag_results) {
        detailsHtml += '<div class="rag-results">';
        for (const rag of step.details.rag_results) {
            const scorePercent = ((rag.top_score || 0) * 100).toFixed(0);
            detailsHtml += `
                <div class="rag-result-item">
                    <span class="rag-source">${rag.source}:</span>
                    <span class="rag-matches">${rag.matches} matches</span>
                    <div class="rag-score-bar">
                        <div class="rag-score-fill" style="width: ${scorePercent}%"></div>
                    </div>
                    <span>${scorePercent}%</span>
                </div>
            `;
        }
        detailsHtml += '</div>';
    } else if (step.step_type === 'context_building') {
        const totalSize = (step.details.doc_context_size || 0) + 
                          (step.details.detection_context_size || 0) + 
                          (step.details.cim_context_size || 0);
        detailsHtml += `<div class="step-detail-item">Context: ${(totalSize / 1000).toFixed(1)}KB of relevant data</div>`;
    } else if (step.step_type === 'query_generation') {
        if (step.details.query_preview) {
            detailsHtml += `<div class="step-detail-item">${escapeHtml(step.details.query_preview.substring(0, 60))}...</div>`;
        }
    } else if (step.step_type === 'validation') {
        if (step.details.validated !== undefined) {
            detailsHtml += `<div class="step-detail-item">Status: ${step.details.validated ? '✓ Valid' : '✗ Invalid'}</div>`;
        }
        if (step.details.result_count !== undefined) {
            detailsHtml += `<div class="step-detail-item">Results: ${step.details.result_count} events</div>`;
        }
    } else if (step.step_type === 'refinement') {
        if (step.details.iteration) {
            detailsHtml += `<div class="step-detail-item">Iteration: ${step.details.iteration}</div>`;
        }
        if (step.details.reason) {
            detailsHtml += `<div class="step-detail-item">Reason: ${escapeHtml(step.details.reason)}</div>`;
        }
    }
    
    const duration = step.duration_ms > 0 ? `<span class="step-duration">${(step.duration_ms / 1000).toFixed(2)}s</span>` : '';
    
    return `
        <div class="reasoning-step">
            <div class="step-icon ${step.status}">${icon}</div>
            <div class="step-content">
                <div class="step-title">${escapeHtml(step.title)}</div>
                <div class="step-details">${detailsHtml}</div>
            </div>
            ${duration}
        </div>
    `;
}

function toggleReasoningPanel(panel) {
    panel.classList.toggle('expanded');
}

async function sendMessage() {
    const input = elements.userInput.value.trim();
    if (!input || state.isLoading) return;
    
    state.isLoading = true;
    elements.sendBtn.disabled = true;
    
    // Add user message
    addMessage('user', `<p>${escapeHtml(input)}</p>`);
    elements.userInput.value = '';
    
    // Add loading message
    const loadingMsg = addLoadingMessage();
    
    // Use show_reasoning based on toggle
    const showReasoning = elements.showReasoningToggle?.checked ?? true;
    
    try {
        // Use regular API - steps animate via CSS while waiting
        const result = await window.api.generateQuery(input, showReasoning);
        
        // Track session tokens
        if (result.token_usage) {
            state.sessionTokens.total += result.token_usage.total_tokens || 0;
            state.sessionTokens.input += result.token_usage.total_input_tokens || 0;
            state.sessionTokens.output += result.token_usage.total_output_tokens || 0;
        }
        
        // Replace loading message with result
        loadingMsg.querySelector('.message-content').innerHTML = formatQueryResult(result);
        
        // Auto-expand reasoning panel if it exists
        if (showReasoning) {
            const reasoningPanel = loadingMsg.querySelector('.reasoning-panel');
            if (reasoningPanel) {
                setTimeout(() => reasoningPanel.classList.add('expanded'), 100);
            }
        }
        
    } catch (error) {
        loadingMsg.querySelector('.message-content').innerHTML = `
            <p style="color: var(--accent-error);">Error: ${escapeHtml(error.message)}</p>
            <p>Please check your configuration and try again.</p>
        `;
    }
    
    state.isLoading = false;
    elements.sendBtn.disabled = false;
    
    // Refresh status to update token count
    updateStatus();
}

async function sendE2EWorkflow() {
    const url = elements.e2eUrl?.value.trim();
    const file = elements.e2eFile?.files[0];
    
    if (!url && !file) return;
    if (state.isLoading) return;
    
    state.isLoading = true;
    elements.sendE2EBtn.disabled = true;
    
    const validateSplunk = elements.e2eValidateSplunk?.checked ?? true;
    const testAttack = elements.e2eTestAttack?.checked ?? true;
    
    // Add user message
    const inputDesc = url ? `E2E Workflow: ${url}` : `E2E Workflow: ${file.name}`;
    addMessage('user', `<p>🔄 ${escapeHtml(inputDesc)}</p>`);
    
    // Clear inputs
    if (elements.e2eUrl) elements.e2eUrl.value = '';
    if (elements.e2eFile) elements.e2eFile.value = '';
    
    // Add loading message with E2E stages
    const loadingMsg = addMessage('assistant', `
        <div class="loading">
            <span>Running End-to-End Workflow</span>
            <div class="loading-dots">
                <span></span>
                <span></span>
                <span></span>
            </div>
        </div>
        <div class="e2e-progress">
            <div class="e2e-stage" data-stage="input">
                <span class="stage-icon">⏳</span>
                <span>Processing IOC source...</span>
            </div>
            <div class="e2e-stage" data-stage="extraction">
                <span class="stage-icon">○</span>
                <span>Extracting IOCs</span>
            </div>
            <div class="e2e-stage" data-stage="detection">
                <span class="stage-icon">○</span>
                <span>Building detection</span>
            </div>
            <div class="e2e-stage" data-stage="practices">
                <span class="stage-icon">○</span>
                <span>Checking best practices</span>
            </div>
            <div class="e2e-stage" data-stage="validation">
                <span class="stage-icon">○</span>
                <span>Validating with Splunk</span>
            </div>
            <div class="e2e-stage" data-stage="attack">
                <span class="stage-icon">○</span>
                <span>Testing against attack data</span>
            </div>
        </div>
    `);
    
    try {
        const result = await window.api.runE2EWorkflow(url, file, validateSplunk, testAttack);
        
        loadingMsg.querySelector('.message-content').innerHTML = formatE2EResult(result);
        
    } catch (error) {
        loadingMsg.querySelector('.message-content').innerHTML = `
            <p style="color: var(--accent-error);">Error: ${escapeHtml(error.message)}</p>
            <p>Please check your configuration and try again.</p>
        `;
    }
    
    state.isLoading = false;
    elements.sendE2EBtn.disabled = false;
    
    // Refresh status to update token count
    updateStatus();
}

function formatE2EResult(result) {
    const statusClass = result.success ? 'success' : 'failed';
    const statusIcon = result.success ? '✓' : '✗';
    const confidencePercent = Math.round((result.confidence_score || 0) * 100);
    
    // Format stages
    const stagesHtml = result.stages?.map(stage => {
        const stageIcons = {
            'success': '✓',
            'warning': '⚠️',
            'failed': '✗',
            'skipped': '⏭️',
            'in_progress': '🔄',
            'pending': '○'
        };
        const icon = stageIcons[stage.status] || '•';
        const statusClass = stage.status;
        
        let detailsHtml = '';
        if (stage.details) {
            for (const [key, value] of Object.entries(stage.details)) {
                if (typeof value === 'object') continue;
                detailsHtml += `<div class="stage-detail">${key}: ${value}</div>`;
            }
        }
        if (stage.warnings?.length) {
            detailsHtml += `<div class="stage-warning">⚠️ ${stage.warnings.join(', ')}</div>`;
        }
        
        const duration = stage.duration_ms > 0 ? `<span class="stage-duration">${(stage.duration_ms / 1000).toFixed(2)}s</span>` : '';
        
        return `
            <div class="e2e-stage-result ${statusClass}">
                <span class="stage-icon">${icon}</span>
                <div class="stage-content">
                    <div class="stage-title">${escapeHtml(stage.title)}</div>
                    <div class="stage-details">${detailsHtml}</div>
                </div>
                ${duration}
            </div>
        `;
    }).join('') || '';
    
    // Format IOC summary
    let iocHtml = '';
    if (result.ioc_count > 0) {
        iocHtml = `
            <div class="e2e-section">
                <h4>📋 IOCs Extracted (${result.ioc_count})</h4>
                <div class="ioc-types">
                    ${Object.entries(result.ioc_types || {}).map(([type, count]) => 
                        `<span class="ioc-type-badge">${type}: ${count}</span>`
                    ).join('')}
                </div>
                ${result.ttps_detected?.length ? `<div class="ttps">TTPs: ${result.ttps_detected.join(', ')}</div>` : ''}
            </div>
        `;
    }
    
    // Format attack data matches
    let attackHtml = '';
    if (result.attack_data_matches?.length > 0) {
        attackHtml = `
            <div class="e2e-section">
                <h4>🎯 Attack Data Matches (${result.attack_data_match_count})</h4>
                <div class="attack-matches">
                    ${result.attack_data_matches.slice(0, 5).map(match => `
                        <div class="attack-match">
                            <span class="match-name">${escapeHtml(match.dataset_name)}</span>
                            ${match.mitre_id ? `<span class="match-mitre">${match.mitre_id}</span>` : ''}
                            <span class="match-score">${(match.relevance_score * 100).toFixed(0)}%</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
    
    // Store the E2E query in cache for copy
    const e2eQueryId = 'e2e-query-' + Date.now();
    window._queryCache = window._queryCache || {};
    window._queryCache[e2eQueryId] = result.spl_query || '';
    
    return `
        <div class="query-result ${statusClass}">
            <pre class="spl-query"><code>${escapeHtml(result.spl_query || 'No query generated')}</code></pre>
            <button class="copy-btn" data-query-id="${e2eQueryId}" onclick="copyQueryById(this)">Copy</button>
        </div>
        
        ${result.explanation ? `<p class="explanation"><strong>Explanation:</strong> ${escapeHtml(result.explanation)}</p>` : ''}
        
        <div class="result-meta">
            <span class="meta-item status-${statusClass}">Status: ${statusIcon} ${result.success ? 'success' : 'failed'}</span>
            <span class="meta-item">Time: ${(result.total_time_ms / 1000).toFixed(2)}s</span>
            ${result.query_validated ? `<span class="meta-item">Validated: ${result.validation_result_count} results</span>` : ''}
            <span class="meta-item">Confidence: ${confidencePercent}%</span>
        </div>
        
        ${iocHtml}
        ${attackHtml}
        
        <div class="e2e-workflow-panel">
            <div class="e2e-header" onclick="this.parentElement.classList.toggle('expanded')">
                <span>🔄 Workflow Stages</span>
                <div class="confidence-bar">
                    <div class="confidence-fill" style="width: ${confidencePercent}%"></div>
                    <span>${confidencePercent}%</span>
                </div>
                <span class="e2e-expand">▼</span>
            </div>
            <div class="e2e-body">
                <div class="e2e-stages">
                    ${stagesHtml}
                </div>
            </div>
        </div>
        
        ${result.warnings?.length ? `
            <div class="warnings">
                ${result.warnings.map(w => `<div class="warning-item">⚠️ ${escapeHtml(w)}</div>`).join('')}
            </div>
        ` : ''}
        
        ${result.errors?.length ? `
            <div class="errors">
                ${result.errors.map(e => `<div class="error-item">❌ ${escapeHtml(e)}</div>`).join('')}
            </div>
        ` : ''}
    `;
}

async function sendIOC() {
    const url = elements.iocUrl.value.trim();
    const file = elements.iocFile.files[0];
    
    if (!url && !file) return;
    if (state.isLoading) return;
    
    state.isLoading = true;
    elements.sendIOCBtn.disabled = true;
    
    // Add user message
    const inputDesc = url ? `IOC Report URL: ${url}` : `IOC File: ${file.name}`;
    addMessage('user', `<p>${escapeHtml(inputDesc)}</p>`);
    
    // Clear inputs
    elements.iocUrl.value = '';
    elements.iocFile.value = '';
    
    // Add loading message
    const loadingMsg = addLoadingMessage();
    
    try {
        const result = url 
            ? await window.api.processIOCUrl(url)
            : await window.api.processIOCFile(file);
        
        loadingMsg.querySelector('.message-content').innerHTML = formatQueryResult(result);
        
    } catch (error) {
        loadingMsg.querySelector('.message-content').innerHTML = `
            <p style="color: var(--accent-error);">Error: ${escapeHtml(error.message)}</p>
        `;
    }
    
    state.isLoading = false;
    elements.sendIOCBtn.disabled = false;
}

// =============================================================================
// SEARCH
// =============================================================================

async function performSearch() {
    const query = elements.searchQuery.value.trim();
    if (!query) return;
    
    elements.searchBtn.disabled = true;
    elements.searchBtn.textContent = 'Searching...';
    
    try {
        const ragType = elements.searchRagType.value;
        const results = await window.api.search(query, ragType);
        
        if (results.results.length === 0) {
            elements.searchResults.innerHTML = `
                <p style="color: var(--text-secondary); text-align: center; padding: 32px;">
                    No results found for "${escapeHtml(query)}"
                </p>
            `;
        } else {
            elements.searchResults.innerHTML = results.results.map(result => `
                <div class="search-result-item">
                    <div class="search-result-header">
                        <span class="search-result-source ${result.source}">${result.source.replace('_', ' ')}</span>
                        <span class="search-result-score">Score: ${result.score.toFixed(2)}</span>
                    </div>
                    <div class="search-result-content">${escapeHtml(result.content)}</div>
                </div>
            `).join('');
        }
        
    } catch (error) {
        elements.searchResults.innerHTML = `
            <p style="color: var(--accent-error);">Error: ${escapeHtml(error.message)}</p>
        `;
    }
    
    elements.searchBtn.disabled = false;
    elements.searchBtn.textContent = 'Search';
}

// =============================================================================
// SETTINGS
// =============================================================================

async function loadConfig() {
    try {
        const config = await window.api.getConfig();
        state.config = config;
        
        if (config.llm_provider) elements.llmProvider.value = config.llm_provider;
        if (config.llm_model) elements.llmModel.value = config.llm_model;
        if (config.splunk_host) elements.splunkHost.value = config.splunk_host;
        if (config.splunk_port) elements.splunkPort.value = config.splunk_port;
        elements.splunkVerifySSL.checked = config.splunk_verify_ssl !== false;
        
    } catch (error) {
        console.error('Failed to load config:', error);
    }
}

async function saveConfig() {
    const config = {
        llm_provider: elements.llmProvider.value || undefined,
        llm_api_key: elements.llmApiKey.value || undefined,
        llm_model: elements.llmModel.value || undefined,
        splunk_host: elements.splunkHost.value || undefined,
        splunk_port: elements.splunkPort.value ? parseInt(elements.splunkPort.value) : undefined,
        splunk_token: elements.splunkToken.value || undefined,
        splunk_verify_ssl: elements.splunkVerifySSL.checked,
    };
    
    elements.saveConfigBtn.disabled = true;
    elements.saveConfigBtn.textContent = 'Saving...';
    
    try {
        await window.api.updateConfig(config);
        elements.saveConfigBtn.textContent = 'Saved!';
        
        // Refresh status
        setTimeout(() => {
            updateStatus();
            elements.saveConfigBtn.textContent = 'Save Configuration';
            elements.saveConfigBtn.disabled = false;
        }, 1000);
        
    } catch (error) {
        elements.saveConfigBtn.textContent = 'Error!';
        setTimeout(() => {
            elements.saveConfigBtn.textContent = 'Save Configuration';
            elements.saveConfigBtn.disabled = false;
        }, 2000);
    }
}

async function testSplunkConnection() {
    elements.testSplunkBtn.disabled = true;
    elements.testSplunkBtn.textContent = 'Testing...';
    elements.splunkTestResult.textContent = '';
    
    try {
        const result = await window.api.testSplunkConnection();
        
        if (result.connected) {
            elements.splunkTestResult.textContent = `✓ Connected (${result.server_name} v${result.version})`;
            elements.splunkTestResult.className = 'test-result success';
        } else {
            elements.splunkTestResult.textContent = `✗ ${result.error || 'Connection failed'}`;
            elements.splunkTestResult.className = 'test-result error';
        }
        
    } catch (error) {
        elements.splunkTestResult.textContent = `✗ ${error.message}`;
        elements.splunkTestResult.className = 'test-result error';
    }
    
    elements.testSplunkBtn.disabled = false;
    elements.testSplunkBtn.textContent = 'Test Connection';
}

// =============================================================================
// UTILITIES
// =============================================================================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function copyToClipboard(button, text) {
    // Try modern clipboard API first, fallback to legacy method
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            showCopySuccess(button);
        }).catch(() => {
            legacyCopy(text, button);
        });
    } else {
        legacyCopy(text, button);
    }
}

function legacyCopy(text, button) {
    // Fallback for non-HTTPS contexts
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    try {
        document.execCommand('copy');
        showCopySuccess(button);
    } catch (err) {
        console.error('Copy failed:', err);
        button.textContent = 'Failed';
        setTimeout(() => { button.textContent = 'Copy'; }, 2000);
    }
    document.body.removeChild(textarea);
}

function showCopySuccess(button) {
    button.classList.add('copied');
    button.textContent = 'Copied!';
    setTimeout(() => {
        button.classList.remove('copied');
        button.textContent = 'Copy';
    }, 2000);
}

function copyQueryById(button) {
    const queryId = button.dataset.queryId;
    const text = window._queryCache?.[queryId] || '';
    if (text) {
        copyToClipboard(button, text);
    }
}

// Make functions available globally
window.copyToClipboard = copyToClipboard;
window.copyQueryById = copyQueryById;
window.toggleReasoningPanel = toggleReasoningPanel;

// =============================================================================
// EVENT LISTENERS
// =============================================================================

function initEventListeners() {
    // Navigation
    elements.navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            switchView(item.dataset.view);
        });
    });
    
    // Chat mode toggle
    elements.modeButtons.forEach(btn => {
        btn.addEventListener('click', () => switchInputMode(btn.dataset.mode));
    });
    
    // Example query buttons
    document.querySelectorAll('.example-query-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const query = btn.dataset.query;
            if (query) {
                // Switch to text mode if not already
                switchInputMode('text');
                // Set the input value
                elements.userInput.value = query;
                // Focus the input
                elements.userInput.focus();
                // Optionally auto-submit
                sendMessage();
            }
        });
    });
    
    // Send message
    elements.sendBtn.addEventListener('click', sendMessage);
    elements.userInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });
    
    // Send IOC
    elements.sendIOCBtn.addEventListener('click', sendIOC);
    
    // Send E2E Workflow
    if (elements.sendE2EBtn) {
        elements.sendE2EBtn.addEventListener('click', sendE2EWorkflow);
    }
    
    // Search
    elements.searchBtn.addEventListener('click', performSearch);
    elements.searchQuery.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') performSearch();
    });
    
    // Settings
    elements.testSplunkBtn.addEventListener('click', testSplunkConnection);
    elements.saveConfigBtn.addEventListener('click', saveConfig);
}

// =============================================================================
// INITIALIZATION
// =============================================================================

async function init() {
    initEventListeners();
    await updateStatus();
    
    // Refresh status periodically
    setInterval(updateStatus, 30000);
}

// Start the app
document.addEventListener('DOMContentLoaded', init);
