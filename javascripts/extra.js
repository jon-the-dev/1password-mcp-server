// Custom JavaScript for 1Password MCP Server documentation

document.addEventListener('DOMContentLoaded', function() {
    // Add copy button functionality to code blocks
    const codeBlocks = document.querySelectorAll('pre code');
    codeBlocks.forEach(function(block) {
        const button = document.createElement('button');
        button.className = 'md-clipboard md-clipboard--inline';
        button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M19,21H8V7H19M19,5H8A2,2 0 0,0 6,7V21A2,2 0 0,0 8,23H19A2,2 0 0,0 21,21V7A2,2 0 0,0 19,5M16,1H4A2,2 0 0,0 2,3V17H4V3H16V1Z"></path></svg>';
        button.title = 'Copy to clipboard';
        
        block.parentNode.style.position = 'relative';
        block.parentNode.appendChild(button);
        
        button.addEventListener('click', function() {
            navigator.clipboard.writeText(block.textContent).then(function() {
                button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M21,7L9,19L3.5,13.5L4.91,12.09L9,16.17L19.59,5.59L21,7Z"></path></svg>';
                setTimeout(function() {
                    button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M19,21H8V7H19M19,5H8A2,2 0 0,0 6,7V21A2,2 0 0,0 8,23H19A2,2 0 0,0 21,21V7A2,2 0 0,0 19,5M16,1H4A2,2 0 0,0 2,3V17H4V3H16V1Z"></path></svg>';
                }, 2000);
            });
        });
    });

    // Add environment detection for configuration examples
    const userAgent = navigator.userAgent;
    const isWindows = userAgent.indexOf('Windows') !== -1;
    const isMac = userAgent.indexOf('Mac') !== -1;
    const isLinux = userAgent.indexOf('Linux') !== -1;

    // Update configuration file paths based on OS
    const configPaths = document.querySelectorAll('.config-path');
    configPaths.forEach(function(element) {
        if (isWindows) {
            element.textContent = element.textContent.replace('~/', '%APPDATA%/');
        } else if (isMac) {
            element.textContent = element.textContent.replace('~/.config/', '~/Library/Application Support/');
        }
    });

    // Add security warning for token display
    const tokenElements = document.querySelectorAll('code:contains("ops_")');
    tokenElements.forEach(function(element) {
        if (element.textContent.includes('ops_your_') || element.textContent.includes('ops_test_')) {
            element.style.position = 'relative';
            const warning = document.createElement('span');
            warning.className = 'security-badge';
            warning.textContent = 'Example Token';
            warning.style.position = 'absolute';
            warning.style.top = '-8px';
            warning.style.right = '-8px';
            warning.style.fontSize = '0.7em';
            element.parentNode.style.position = 'relative';
            element.parentNode.appendChild(warning);
        }
    });

    // Add status indicators for health checks
    const healthElements = document.querySelectorAll('.health-status');
    healthElements.forEach(function(element) {
        const status = element.textContent.toLowerCase();
        if (status.includes('healthy')) {
            element.className += ' status-healthy';
        } else if (status.includes('warning')) {
            element.className += ' status-warning';
        } else if (status.includes('error') || status.includes('failed')) {
            element.className += ' status-error';
        }
    });

    // Smooth scrolling for anchor links
    const anchorLinks = document.querySelectorAll('a[href^="#"]');
    anchorLinks.forEach(function(link) {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Add version badge to navigation
    const version = '1.1.0';
    const navTitle = document.querySelector('.md-nav--primary .md-nav__title');
    if (navTitle) {
        const versionBadge = document.createElement('span');
        versionBadge.className = 'version-badge';
        versionBadge.textContent = 'v' + version;
        navTitle.appendChild(versionBadge);
    }

    // Enhanced code block language detection
    const codeLanguageMap = {
        'bash': 'Shell',
        'json': 'JSON',
        'python': 'Python',
        'yaml': 'YAML',
        'javascript': 'JavaScript'
    };

    document.querySelectorAll('pre code[class*="language-"]').forEach(function(block) {
        const classList = block.className.split(' ');
        const langClass = classList.find(cls => cls.startsWith('language-'));
        if (langClass) {
            const lang = langClass.replace('language-', '');
            const displayName = codeLanguageMap[lang] || lang.toUpperCase();
            
            const label = document.createElement('span');
            label.className = 'code-language-label';
            label.textContent = displayName;
            label.style.position = 'absolute';
            label.style.top = '8px';
            label.style.right = '8px';
            label.style.background = 'rgba(0,0,0,0.3)';
            label.style.color = 'white';
            label.style.padding = '2px 6px';
            label.style.borderRadius = '3px';
            label.style.fontSize = '0.7em';
            
            block.parentNode.style.position = 'relative';
            block.parentNode.appendChild(label);
        }
    });
});

// Add mermaid theme switching support
if (typeof mermaid !== 'undefined') {
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.attributeName === 'data-md-color-scheme') {
                const scheme = document.documentElement.getAttribute('data-md-color-scheme');
                mermaid.initialize({
                    theme: scheme === 'slate' ? 'dark' : 'default'
                });
                
                // Re-render existing mermaid diagrams
                document.querySelectorAll('.mermaid').forEach(function(element) {
                    if (element.hasAttribute('data-processed')) {
                        element.removeAttribute('data-processed');
                        element.innerHTML = element.getAttribute('data-original-text') || element.innerHTML;
                    }
                });
                mermaid.init();
            }
        });
    });

    observer.observe(document.documentElement, {
        attributes: true,
        attributeFilter: ['data-md-color-scheme']
    });
}

// Add external link indicators
document.querySelectorAll('a[href^="http"]').forEach(function(link) {
    if (!link.hostname.includes(window.location.hostname)) {
        link.setAttribute('target', '_blank');
        link.setAttribute('rel', 'noopener noreferrer');
        
        const icon = document.createElement('span');
        icon.innerHTML = ' ↗';
        icon.style.fontSize = '0.8em';
        icon.style.opacity = '0.7';
        link.appendChild(icon);
    }
});

// Analytics and usage tracking (if needed)
function trackDocumentationUsage(action, page) {
    // Placeholder for analytics integration
    console.log('Documentation usage:', action, page);
}

// Track page views
trackDocumentationUsage('page_view', window.location.pathname);