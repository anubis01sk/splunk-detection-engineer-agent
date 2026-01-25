/**
 * Splunk Agent API Client
 * =======================
 * 
 * JavaScript client for communicating with the FastAPI backend.
 */

const API_BASE = '/api';

/**
 * API Client class for all backend communication
 */
class SplunkAgentAPI {
    constructor(baseUrl = API_BASE) {
        this.baseUrl = baseUrl;
    }

    /**
     * Make an API request
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        
        // Don't set Content-Type for FormData - browser sets it with boundary
        const isFormData = options.body instanceof FormData;
        
        const defaultHeaders = isFormData ? {} : {
            'Content-Type': 'application/json',
        };
        
        const mergedOptions = {
            ...options,
            headers: {
                ...defaultHeaders,
                ...(options.headers || {}),
            },
        };
        
        try {
            const response = await fetch(url, mergedOptions);
            
            if (!response.ok) {
                const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
                throw new Error(error.detail || `HTTP ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error(`API Error [${endpoint}]:`, error);
            throw error;
        }
    }

    /**
     * Health check
     */
    async health() {
        return this.request('/health');
    }

    /**
     * Get agent status
     */
    async status() {
        return this.request('/status');
    }

    /**
     * Generate SPL query from user input
     * @param {string} input - User query
     * @param {boolean} showReasoning - Include Chain of Thought reasoning
     * @param {object} options - Additional options
     */
    async generateQuery(input, showReasoning = false, options = {}) {
        return this.request('/query', {
            method: 'POST',
            body: JSON.stringify({ 
                input, 
                show_reasoning: showReasoning,
                options 
            }),
        });
    }

    /**
     * Generate SPL query with real-time streaming updates
     * @param {string} input - User query
     * @param {boolean} showReasoning - Include Chain of Thought reasoning  
     * @param {function} onStep - Callback for each reasoning step
     * @param {object} options - Additional options
     * @returns {Promise} Final result
     */
    async generateQueryStream(input, showReasoning = true, onStep = null, options = {}) {
        const url = `${this.baseUrl}/query/stream`;
        
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                input,
                show_reasoning: showReasoning,
                options
            }),
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
            throw new Error(error.detail || `HTTP ${response.status}`);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let finalResult = null;

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || ''; // Keep incomplete line in buffer

            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    try {
                        const event = JSON.parse(line.slice(6));
                        
                        if (event.type === 'step' && onStep) {
                            // Step data is in event.data
                            onStep(event.data);
                        } else if (event.type === 'complete') {
                            // Final result is in event.data
                            finalResult = event.data;
                        } else if (event.type === 'error') {
                            // Error message is in event.data
                            throw new Error(event.data);
                        }
                        // Ignore 'keepalive' events
                    } catch (e) {
                        // Only re-throw if it's our own error
                        if (e.message && !e.message.includes('JSON')) {
                            throw e;
                        }
                        console.warn('SSE parse warning:', line);
                    }
                }
            }
        }

        return finalResult;
    }

    /**
     * Generate SPL query from IOC report URL
     */
    async processIOCUrl(url) {
        const formData = new FormData();
        formData.append('url', url);
        
        return this.request('/query/ioc', {
            method: 'POST',
            headers: {}, // Let browser set content-type for FormData
            body: formData,
        });
    }

    /**
     * Generate SPL query from IOC file upload
     */
    async processIOCFile(file) {
        const formData = new FormData();
        formData.append('file', file);
        
        return this.request('/query/ioc', {
            method: 'POST',
            headers: {}, // Let browser set content-type for FormData
            body: formData,
        });
    }

    /**
     * Get current configuration
     */
    async getConfig() {
        return this.request('/config');
    }

    /**
     * Update configuration
     */
    async updateConfig(config) {
        return this.request('/config', {
            method: 'POST',
            body: JSON.stringify(config),
        });
    }

    /**
     * Test Splunk connection
     */
    async testSplunkConnection() {
        return this.request('/config/test-splunk', {
            method: 'POST',
        });
    }

    /**
     * Search RAG systems
     */
    async search(query, ragType = 'all', topK = 5) {
        return this.request('/search', {
            method: 'POST',
            body: JSON.stringify({
                query,
                rag_type: ragType,
                top_k: topK,
            }),
        });
    }

    /**
     * Run End-to-End IOC → Detection → Validation workflow
     * @param {string} url - IOC report URL (optional)
     * @param {File} file - IOC report file (optional)
     * @param {boolean} validateSplunk - Validate against Splunk
     * @param {boolean} testAttack - Test against attack data
     */
    async runE2EWorkflow(url, file, validateSplunk = true, testAttack = true) {
        const formData = new FormData();
        
        if (url) {
            formData.append('url', url);
        }
        if (file) {
            formData.append('file', file);
        }
        formData.append('validate_splunk', validateSplunk);
        formData.append('test_attack_data', testAttack);
        
        return this.request('/workflow/e2e', {
            method: 'POST',
            headers: {}, // Let browser set content-type for FormData
            body: formData,
        });
    }
}

// Create global API instance
window.api = new SplunkAgentAPI();
