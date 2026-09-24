(() => {
    'use strict';
    const root = document.querySelector('.tm-page');
    const payload = document.getElementById('tmModelData');
    if (!root || !payload) return;
    let model;
    try { model = JSON.parse(payload.textContent); } catch (_) { return; }
    if (!Array.isArray(model.paths) || !model.paths.length) return;

    const scanId = root.dataset.scanId;
    const list = document.getElementById('tmPathList');
    const search = document.getElementById('tmPathSearch');
    const count = document.getElementById('tmPathCount');
    const noResults = document.getElementById('tmNoResults');
    const canvas = document.getElementById('tmCanvas');
    const note = document.getElementById('tmNodeNote');
    let selected = Number(root.dataset.selected || 0);
    if (!Number.isInteger(selected) || selected < 0 || selected >= model.paths.length) selected = 0;
    let cy = null;

    const setText = (id, value) => { document.getElementById(id).textContent = value || ''; };
    const replaceList = (id, values, tag = 'li') => {
        const parent = document.getElementById(id);
        const children = (values || []).map(value => {
            const item = document.createElement(tag);
            item.textContent = value;
            return item;
        });
        parent.replaceChildren(...children);
    };
    const addEvidence = (parent, title, detail, href) => {
        const row = document.createElement('div');
        row.className = 'tm-evidence-row';
        const heading = document.createElement('strong');
        heading.textContent = title;
        row.append(heading);
        if (detail) {
            const small = document.createElement('small');
            small.textContent = detail;
            row.append(small);
        }
        if (href) {
            const link = document.createElement('a');
            link.href = href;
            link.textContent = 'Open in report';
            row.append(link);
        }
        parent.append(row);
    };

    function renderDetail(path) {
        setText('tmHeadline', path.headline);
        setText('tmBoundary', path.boundary + ' · ' + path.evidence_level);
        setText('tmObserved', path.observed);
        setText('tmCounter', path.counter_hypothesis);
        setText('tmVerification', path.verification);
        replaceList('tmQuestions', path.questions);
        replaceList('tmUnknowns', path.unresolved.length ? path.unresolved :
            ['No graph-specific gap was recorded. Runtime execution and impact are still unproven.']);
        const lenses = document.getElementById('tmLenses');
        lenses.replaceChildren(...path.threat_lenses.map(lens => {
            const tag = document.createElement('span');
            tag.textContent = lens + ' question';
            return tag;
        }));
        const evidence = document.getElementById('tmEvidence');
        evidence.replaceChildren();
        addEvidence(evidence, 'Manifest declaration', path.manifest_source +
            (path.manifest_line ? ':' + path.manifest_line : ' · line unavailable'));
        if (path.handler_source) addEvidence(evidence, 'Recovered handler class', path.handler_source);
        if (path.manifest_permission) addEvidence(evidence, 'Declared permission', path.manifest_permission);
        path.deep_links.forEach(link => addEvidence(evidence, 'Manifest deep link',
            (link.scheme || 'scheme unknown') + '://' + (link.host || 'host unknown') + (link.path || '')));
        path.permission_checks.slice(0, 4).forEach(check => addEvidence(evidence,
            'Permission-check call in class', (check.source || '') + ':' + (check.line || '?') +
            ' · enforcement on this path unproven'));
        path.effects.slice(0, 6).forEach(effect => addEvidence(evidence,
            (effect.symbol || 'Selected call') + ' · ' + (effect.kind || 'effect'),
            (effect.source || '') + ':' + (effect.line || '?') + ' · ' + (effect.relationship || '')));
        path.url_literals.forEach(item => addEvidence(evidence, 'URL literal in handler file',
            item.url + ' · ' + item.source + ':' + (item.line || '?') +
            ' · request target unproven'));
        path.findings.forEach(finding => addEvidence(evidence,
            finding.title + ' · ' + finding.severity,
            finding.relationship + ' · ' + finding.file + ':' + (finding.line || '?'),
            '/history/report/' + encodeURIComponent(scanId) + '#finding-' + finding.index));
        if (!path.findings.length) addEvidence(evidence, 'No linked static rule signal',
            'The diagram is built from entry point evidence alone.');
        const attackLink = document.getElementById('tmAttackLink');
        attackLink.href = '/attack-graph/' + encodeURIComponent(scanId) + '#entry-' + (path.index + 1);
        const runtimeLink = document.getElementById('tmRuntimeLink');
        const testable = ['activity', 'activity-alias'].includes(path.kind) &&
            path.exported === 'explicit true' && !path.manifest_permission;
        runtimeLink.hidden = !testable;
        if (testable) runtimeLink.href = '/runtime-proof/' + encodeURIComponent(scanId) +
            '?path=' + path.index + '#path-' + path.index;
    }

    function graphElements(path) {
        const width = canvas.clientWidth;
        const height = Math.max(canvas.clientHeight, 400);
        const mobile = width < 500 && !document.fullscreenElement;
        const positions = [0.1, 0.29, 0.49, 0.69, 0.9];
        const effectCount = Math.max(1, path.diagram.nodes.length - 4);
        const elements = path.diagram.nodes.map((node, index) => {
            let x;
            let y;
            if (mobile) {
                x = index < 4 ? width * 0.5 : width * (index % 2 === 0 ? 0.28 : 0.72);
                y = index < 4 ? 70 + index * 105 : 500 + Math.floor((index - 4) / 2) * 110;
            } else {
                x = width * positions[Math.min(index, 4)];
                y = height * 0.5;
                if (index >= 4) {
                    x = width * positions[4];
                    y = height * (0.5 + (index - 4 - (effectCount - 1) / 2) * 0.18);
                }
            }
            return { data: { id: node.id, label: node.label, kind: node.kind,
                            detail: node.detail, zone: node.zone }, position: { x, y } };
        });
        path.diagram.edges.forEach((edge, index) => elements.push({
            data: { id: path.id + '-edge-' + index, source: edge.source, target: edge.target,
                    label: edge.label, strength: edge.strength }
        }));
        return elements;
    }

    function renderGraph(path) {
        if (!cy) return;
        const mobile = canvas.clientWidth < 500 && !document.fullscreenElement;
        const effectCount = Math.max(1, path.diagram.nodes.length - 4);
        canvas.parentElement.style.height = mobile ?
            (565 + Math.ceil(effectCount / 2) * 110) + 'px' : '';
        cy.resize();
        cy.elements().remove();
        cy.add(graphElements(path));
        cy.layout({ name: 'preset', fit: true, padding: 18, animate: false }).run();
        cy.fit(cy.elements(), 18);
        note.textContent = path.diagram.effects_hidden ?
            path.diagram.effects_hidden + ' other call occurrences are omitted from this diagram; review the entry point graph for their source lines. Lines remain hypotheses until tested.' :
            'Select a graph node to inspect its exact role. Dashed and dotted edges do not prove execution.';
    }

    function choose(index, updateUrl = true) {
        if (!Number.isInteger(index) || index < 0 || index >= model.paths.length) return;
        selected = index;
        const path = model.paths[index];
        list.querySelectorAll('[data-path]').forEach(link => {
            const active = Number(link.dataset.path) === index;
            link.classList.toggle('is-active', active);
            if (active) link.setAttribute('aria-current', 'true');
            else link.removeAttribute('aria-current');
        });
        renderDetail(path);
        renderGraph(path);
        if (updateUrl) history.replaceState(null, '', '?path=' + index);
    }

    list.addEventListener('click', event => {
        const link = event.target.closest('[data-path]');
        if (!link) return;
        event.preventDefault();
        choose(Number(link.dataset.path));
    });
    search.addEventListener('input', () => {
        const query = search.value.trim().toLocaleLowerCase();
        let shown = 0;
        list.querySelectorAll('[data-path]').forEach(link => {
            const path = model.paths[Number(link.dataset.path)];
            const corpus = [path.component, path.headline, path.kind, path.boundary,
                ...path.effects.map(effect => effect.symbol || '')].join(' ').toLocaleLowerCase();
            const visible = !query || corpus.includes(query);
            link.hidden = !visible;
            if (visible) shown += 1;
        });
        count.textContent = shown + ' of ' + model.paths.length + ' paths';
        noResults.hidden = shown !== 0;
    });

    if (typeof window.cytoscape === 'function') {
        cy = window.cytoscape({
            container: canvas,
            elements: [],
            layout: { name: 'preset' },
            minZoom: 0.45,
            maxZoom: 2.5,
            style: [
                { selector: 'node', style: { 'label': 'data(label)', 'shape': 'round-rectangle',
                    'width': 104, 'height': 58, 'background-color': '#EAF4EF',
                    'border-width': 1.5, 'border-color': '#6A9D88', 'color': '#12352F',
                    'font-family': 'IBM Plex Sans, Arial', 'font-size': 11, 'font-weight': 700,
                    'text-wrap': 'wrap', 'text-max-width': 92, 'text-valign': 'center',
                    'text-halign': 'center', 'overlay-opacity': 0 } },
                { selector: 'node[kind = "actor"]', style: { 'shape': 'ellipse', 'width': 96,
                    'background-color': '#E8EEF0', 'border-color': '#8DA4A9', 'color': '#28474C' } },
                { selector: 'node[kind = "dispatch"]', style: { 'shape': 'diamond', 'width': 98,
                    'height': 76, 'background-color': '#FFF4E3', 'border-color': '#C9974D',
                    'color': '#694814', 'font-size': 10, 'text-max-width': 72 } },
                { selector: 'node[kind = "handler"]', style: { 'background-color': '#D8ECE2',
                    'border-color': '#075C53' } },
                { selector: 'node[kind = "unknown"]', style: { 'background-color': '#F3F4F3',
                    'border-color': '#A8B3AF', 'border-style': 'dashed' } },
                { selector: 'node[kind = "effect"]', style: { 'background-color': '#FFF2E5',
                    'border-color': '#C76A3C', 'color': '#653716' } },
                { selector: 'edge', style: { 'width': 2, 'line-color': '#6E9B8B',
                    'target-arrow-color': '#6E9B8B', 'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier' } },
                { selector: 'edge[strength = "hypothesis"], edge[strength = "uncertain"]',
                    style: { 'line-style': 'dotted', 'line-color': '#8FAAA1',
                        'target-arrow-color': '#8FAAA1' } },
                { selector: 'edge[strength = "class_lexical"]',
                    style: { 'line-style': 'dotted', 'line-color': '#C76A3C',
                        'target-arrow-color': '#C76A3C' } },
                { selector: 'edge[strength = "entry_lexical"]',
                    style: { 'line-style': 'dashed', 'line-color': '#C76A3C',
                        'target-arrow-color': '#C76A3C' } },
                { selector: 'node:selected', style: { 'border-width': 4, 'border-color': '#075C53' } }
            ]
        });
        cy.on('tap', 'node', event => {
            const data = event.target.data();
            note.textContent = data.label + ': ' + data.detail;
        });
        cy.on('tap', 'edge', event => {
            const data = event.target.data();
            note.textContent = data.label + ' · ' + data.strength.replaceAll('_', ' ') +
                '. Read the evidence panel before treating this as a real flow.';
        });
        const fullscreen = document.getElementById('tmFullscreen');
        const wrap = document.getElementById('tmCanvasWrap');
        window.apkhuntThreatModel = {
            fit: () => cy.fit(cy.elements(), 18),
            toggleFullscreen: async () => {
                if (document.fullscreenElement === wrap) await document.exitFullscreen();
                else if (wrap.requestFullscreen) await wrap.requestFullscreen();
            }
        };
        document.addEventListener('fullscreenchange', () => {
            fullscreen.textContent = document.fullscreenElement === wrap ? 'Exit full screen' : 'Full screen';
            cy.resize();
            renderGraph(model.paths[selected]);
        });
        let resizeTimer;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => { cy.resize(); renderGraph(model.paths[selected]); }, 150);
        });
    } else {
        note.textContent = 'Graph library unavailable. The evidence and review questions remain below.';
    }
    choose(selected, false);
})();
