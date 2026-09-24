/**
 * Apkhunt - Professional UI Engine
 */

document.addEventListener('DOMContentLoaded', function() {
    initScrollReveal();
    initCounterAnimations();
    initDragDropUpload();
    initTooltips();
    initAnimations();
    initSearchFilters();
    initChartAnimations();
    initCopyToClipboard();
    initExpandCollapse();
    initRiskMeters();
    initNavbarScroll();
});

/**
 * Scroll Reveal Animation
 */
function initScrollReveal() {
    var reveals = document.querySelectorAll('.reveal');
    if (reveals.length === 0) return;

    var observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });

    reveals.forEach(function(el) {
        observer.observe(el);
    });
}

/**
 * Animated Counters
 */
function initCounterAnimations() {
    var counters = document.querySelectorAll('[data-counter]');
    if (counters.length === 0) return;

    var observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
            if (entry.isIntersecting) {
                animateCounter(entry.target);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });

    counters.forEach(function(el) {
        observer.observe(el);
    });

    function animateCounter(el) {
        var target = parseInt(el.dataset.counter, 10);
        if (isNaN(target) || target === 0) return;

        var duration = 1500;
        var start = performance.now();
        var startVal = 0;

        function step(now) {
            var elapsed = now - start;
            var progress = Math.min(elapsed / duration, 1);
            var ease = 1 - Math.pow(1 - progress, 3);
            var current = Math.floor(startVal + (target - startVal) * ease);
            el.textContent = current.toLocaleString();

            if (progress < 1) {
                requestAnimationFrame(step);
            } else {
                el.textContent = target.toLocaleString();
            }
        }

        requestAnimationFrame(step);
    }
}

/**
 * Navbar scroll effect
 */
function initNavbarScroll() {
    var navbar = document.querySelector('.navbar');
    if (!navbar) return;

    window.addEventListener('scroll', function() {
        if (window.scrollY > 50) {
            navbar.style.background = 'rgba(255, 255, 255, 0.98)';
            navbar.style.boxShadow = '0 1px 3px rgba(0,0,0,0.08)';
        } else {
            navbar.style.background = 'rgba(255, 255, 255, 0.95)';
            navbar.style.boxShadow = 'none';
        }
    });
}

/**
 * Drag and Drop File Upload
 */
function initDragDropUpload() {
    var uploadArea = document.querySelector('.upload-area');
    var fileInput = document.getElementById('apk_file');

    if (!uploadArea || !fileInput) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(function(eventName) {
        uploadArea.addEventListener(eventName, function(e) {
            e.preventDefault();
            e.stopPropagation();
        }, false);
    });

    ['dragenter', 'dragover'].forEach(function(eventName) {
        uploadArea.addEventListener(eventName, function() {
            uploadArea.classList.add('dragover');
        }, false);
    });

    ['dragleave', 'drop'].forEach(function(eventName) {
        uploadArea.addEventListener(eventName, function() {
            uploadArea.classList.remove('dragover');
        }, false);
    });

    uploadArea.addEventListener('drop', function(e) {
        var files = e.dataTransfer.files;
        if (files.length > 0) {
            fileInput.files = files;
            updateFileLabel(files[0].name);
        }
    }, false);

    fileInput.addEventListener('change', function() {
        if (this.files.length > 0) {
            updateFileLabel(this.files[0].name);
        }
    });

    function updateFileLabel(fileName) {
        var fileNameDisplay = document.getElementById('fileName');
        if (fileNameDisplay) {
            fileNameDisplay.textContent = fileName;
            fileNameDisplay.classList.remove('text-muted');
            fileNameDisplay.classList.add('file-name');
        }

        var uploadBtn = document.getElementById('uploadBtn');
        if (uploadBtn) {
            uploadBtn.classList.remove('d-none');
        }
    }
}

/**
 * Custom Tooltips
 */
function initTooltips() {
    var tooltipTriggers = document.querySelectorAll('[data-tooltip]');

    tooltipTriggers.forEach(function(trigger) {
        var tooltipText = trigger.getAttribute('data-tooltip');
        var tooltip = document.createElement('span');
        tooltip.classList.add('tooltip-text');
        tooltip.textContent = tooltipText;

        trigger.classList.add('custom-tooltip');
        trigger.appendChild(tooltip);
    });
}

/**
 * Scroll and Fade Animations
 */
function initAnimations() {
    var animateElements = document.querySelectorAll('.animate-on-scroll');
    if (animateElements.length === 0) return;

    var observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-fade-in-up');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });

    animateElements.forEach(function(element) {
        observer.observe(element);
    });

    document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
        anchor.addEventListener('click', function(e) {
            var targetId = this.getAttribute('href');
            if (targetId === '#') return;

            var targetElement = document.querySelector(targetId);
            if (targetElement) {
                e.preventDefault();
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

/**
 * Enhanced Search and Filtering
 */
function initSearchFilters() {
    var searchInput = document.getElementById('searchInput');
    var findingsContainer = document.getElementById('findingsContainer');
    var severityFilters = document.querySelectorAll('.severity-filter-btn');
    var clearFiltersBtn = document.getElementById('clearFiltersBtn');

    if (!searchInput || !findingsContainer) return;

    var activeFilters = {
        severity: null,
        search: '',
        category: null
    };

    function debounce(func, wait) {
        var timeout;
        return function() {
            var context = this;
            var args = arguments;
            clearTimeout(timeout);
            timeout = setTimeout(function() {
                func.apply(context, args);
            }, wait);
        };
    }

    function applyFilters() {
        var findingCards = findingsContainer.querySelectorAll('.finding-card');
        var categoryGroups = findingsContainer.querySelectorAll('.masvs-category-group');
        var visibleCount = 0;
        var categoryCounts = {};

        findingCards.forEach(function(card) {
            var severity = card.dataset.severity;
            var title = (card.dataset.title || '').toLowerCase();
            var desc = (card.dataset.desc || '').toLowerCase();
            var file = (card.dataset.file || '').toLowerCase();
            var id = (card.dataset.id || '').toLowerCase();
            var category = card.closest('.masvs-category-group').dataset.category;

            if (!categoryCounts[category]) {
                categoryCounts[category] = {total: 0, visible: 0};
            }
            categoryCounts[category].total++;

            var matchesSeverity = !activeFilters.severity || severity === activeFilters.severity;
            var matchesSearch = !activeFilters.search ||
                               title.includes(activeFilters.search) ||
                               desc.includes(activeFilters.search) ||
                               file.includes(activeFilters.search) ||
                               id.includes(activeFilters.search);
            var matchesCategory = !activeFilters.category || category === activeFilters.category;
            var isVisible = matchesSeverity && matchesSearch && matchesCategory;

            card.style.display = isVisible ? '' : 'none';

            if (isVisible) {
                visibleCount++;
                categoryCounts[category].visible++;
            }
        });

        categoryGroups.forEach(function(group) {
            var category = group.dataset.category;
            var categoryCount = categoryCounts[category] || {total: 0, visible: 0};
            var countBadge = group.querySelector('.category-count');

            if (countBadge) {
                countBadge.textContent = categoryCount.visible;
            }

            group.style.display = categoryCount.visible > 0 ? '' : 'none';
        });

        var totalCountEl = document.getElementById('totalFindingsCount');
        if (totalCountEl) {
            totalCountEl.textContent = visibleCount;
        }

        if (clearFiltersBtn) {
            var hasActiveFilters = activeFilters.severity || activeFilters.search || activeFilters.category;
            clearFiltersBtn.style.display = hasActiveFilters ? 'inline-block' : 'none';
        }

        updateSidebarCounts(categoryCounts);
    }

    function updateSidebarCounts(categoryCounts) {
        var tocCategoryList = document.getElementById('tocCategoryList');
        if (!tocCategoryList) return;

        Object.entries(categoryCounts).forEach(function(entry) {
            var category = entry[0];
            var counts = entry[1];
            var categoryId = 'masvs-' + category.replace(/\./g, '-').replace(/ /g, '-').toLowerCase();
            var tocSelector = 'a' + '[href="' + '#' + categoryId + '"]';
            var tocLink = tocCategoryList.querySelector(tocSelector);

            if (tocLink) {
                var tocBadge = tocLink.querySelector('.category-count-toc');
                if (tocBadge) {
                    tocBadge.textContent = counts.visible;
                }

                var listItem = tocLink.closest('li');
                if (listItem) {
                    listItem.style.display = counts.visible > 0 ? '' : 'none';
                }
            }
        });
    }

    if (searchInput) {
        searchInput.addEventListener('input', debounce(function() {
            activeFilters.search = this.value.toLowerCase();
            applyFilters();
        }, 300));
    }

    severityFilters.forEach(function(btn) {
        btn.addEventListener('click', function() {
            var severity = this.dataset.severity;

            severityFilters.forEach(function(b) {
                b.classList.remove('active', 'border', 'border-primary', 'border-3');
            });

            if (activeFilters.severity === severity) {
                activeFilters.severity = null;
            } else {
                activeFilters.severity = severity;
                this.classList.add('active', 'border', 'border-primary', 'border-3');
            }

            applyFilters();
        });
    });

    function clearFindingFilters() {
        activeFilters.severity = null;
        activeFilters.search = '';
        activeFilters.category = null;

        severityFilters.forEach(function(b) {
            b.classList.remove('active', 'border', 'border-primary', 'border-3');
        });

        if (searchInput) {
            searchInput.value = '';
        }

        applyFilters();
    }

    window.apkhuntClearFindingFilters = clearFindingFilters;
}

/**
 * Chart Animations
 */
function initChartAnimations() {
    var chartCanvas = document.getElementById('severityChart');

    if (!chartCanvas || typeof Chart === 'undefined') return;

    chartCanvas.addEventListener('mousemove', function(e) {
        var activePoints = window.severityChart && window.severityChart.getElementsAtEventForMode(e, 'nearest', { intersect: true }, false);

        if (activePoints && activePoints.length > 0) {
            chartCanvas.style.cursor = 'pointer';
        } else {
            chartCanvas.style.cursor = 'default';
        }
    });
}

/**
 * Copy to Clipboard
 */
function initCopyToClipboard() {
    document.querySelectorAll('pre code').forEach(function(codeBlock) {
        var container = codeBlock.parentNode;
        var copyButton = document.createElement('button');
        copyButton.className = 'copy-button';
        copyButton.textContent = 'Copy';
        copyButton.style.cssText = 'position:absolute;top:8px;right:8px;padding:4px 10px;font-size:0.7rem;background:#F3F4F6;color:#4F46E5;border:1px solid #E5E7EB;border-radius:6px;cursor:pointer;z-index:5;';

        copyButton.addEventListener('click', function() {
            navigator.clipboard.writeText(codeBlock.textContent)
                .then(function() {
                    copyButton.textContent = 'Copied!';
                    copyButton.style.background = '#DCFCE7';
                    copyButton.style.color = '#16A34A';
                    setTimeout(function() {
                        copyButton.textContent = 'Copy';
                        copyButton.style.background = '#F3F4F6';
                        copyButton.style.color = '#4F46E5';
                    }, 2000);
                })
                .catch(function(err) {
                    console.error('Failed to copy:', err);
                });
        });

        container.style.position = 'relative';
        container.appendChild(copyButton);
    });
}

/**
 * Expand/Collapse All Findings
 */
function initExpandCollapse() {
    var expandAllBtn = document.getElementById('expandAllBtn');
    var collapseAllBtn = document.getElementById('collapseAllBtn');

    if (!expandAllBtn || !collapseAllBtn) return;

    function expandAllFindings() {
        document.querySelectorAll('.finding-card .collapse:not(.show)').forEach(function(cardBody) {
            bootstrap.Collapse.getOrCreateInstance(cardBody).show();
        });
    }

    function collapseAllFindings() {
        document.querySelectorAll('.finding-card .collapse.show').forEach(function(cardBody) {
            bootstrap.Collapse.getOrCreateInstance(cardBody).hide();
        });
    }

    window.apkhuntExpandAllFindings = expandAllFindings;
    window.apkhuntCollapseAllFindings = collapseAllFindings;
}

/**
 * Risk Score Meters
 */
function initRiskMeters() {
    var riskMeters = document.querySelectorAll('.risk-meter');

    riskMeters.forEach(function(meter) {
        var value = parseFloat(meter.dataset.value) || 0;
        var maxValue = parseFloat(meter.dataset.max) || 100;
        var percentage = (value / maxValue) * 100;

        var radius = 54;
        var circumference = 2 * Math.PI * radius;
        var dashOffset = circumference - (percentage / 100) * circumference;

        var circle = meter.querySelector('.risk-meter-value');
        if (circle) {
            circle.style.strokeDasharray = circumference;
            circle.style.strokeDashoffset = dashOffset;

            if (percentage >= 75) {
                circle.style.stroke = '#DC2626';
            } else if (percentage >= 50) {
                circle.style.stroke = '#EA580C';
            } else if (percentage >= 25) {
                circle.style.stroke = '#D97706';
            } else {
                circle.style.stroke = '#16A34A';
            }
        }

        var text = meter.querySelector('.risk-meter-text');
        if (text) {
            text.textContent = Math.round(value);
        }
    });
}

/**
 * Toast notifications
 */
function showToast(message, type) {
    type = type || 'info';

    var toastContainer = document.querySelector('.toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }

    var toast = document.createElement('div');
    toast.className = 'toast align-items-center';
    toast.setAttribute('role', 'alert');
    toast.style.background = '#FFFFFF';
    toast.style.border = '1px solid #E5E7EB';
    toast.style.color = '#111827';

    toast.innerHTML = '<div class="d-flex"><div class="toast-body">' + message + '</div>' +
        '<button type="button" class="btn-close me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button></div>';

    toastContainer.appendChild(toast);

    var bsToast = new bootstrap.Toast(toast, { autohide: true, delay: 5000 });
    bsToast.show();

    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });
}
