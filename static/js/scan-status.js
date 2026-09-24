(function () {
    const dock = document.getElementById('scanJobDock');
    const list = document.getElementById('scanJobList');
    const toggle = document.getElementById('scanJobToggle');
    const count = document.getElementById('scanJobCount');
    if (!dock || !list) return;
    let minimized = window.localStorage.getItem('apkhunt.scanDockMinimized') === 'true';
    function setMinimized(value) {
        minimized = value;
        dock.classList.toggle('is-minimized', value);
        if (toggle) {
            toggle.setAttribute('aria-expanded', String(!value));
            toggle.setAttribute('aria-label', value ? 'Expand scan worker' : 'Minimize scan worker');
            toggle.title = value ? 'Expand scan worker' : 'Minimize scan worker';
            toggle.querySelector('i').className = value ? 'bi bi-plus-lg' : 'bi bi-dash-lg';
        }
        window.localStorage.setItem('apkhunt.scanDockMinimized', String(value));
    }
    window.apkhuntToggleScanDock = () => setMinimized(!minimized);
    setMinimized(minimized);

    const stageLabels = {
        queued: 'Queued',
        decompiling: 'JADX decompilation',
        decompiling_simple: 'JADX simplified retry',
        decompiling_dex: 'JADX DEX recovery',
        fallback: 'Apktool fallback',
        rules: 'Security rules',
        dependencies: 'Dependencies',
        report: 'Saving report',
        completed: 'Completed',
        error: 'Scan stopped'
    };
    let lastFingerprint = '';

    function duration(seconds) {
        const minutes = Math.floor(seconds / 60);
        return minutes ? minutes + 'm ' + Math.floor(seconds % 60) + 's' : Math.floor(seconds) + 's';
    }

    function makeJob(job) {
        const item = document.createElement('section');
        item.className = 'ah-job' + (job.status === 'error' ? ' ah-job--error' : '');
        const top = document.createElement('div');
        top.className = 'ah-job__top';
        const title = document.createElement('strong');
        title.textContent = job.filename || 'APK scan';
        const state = document.createElement('span');
        state.className = 'ah-job__state';
        state.textContent = stageLabels[job.stage] || 'Scanning';
        top.append(title, state);

        const message = document.createElement('p');
        message.className = 'ah-job__message';
        message.textContent = job.status === 'completed' ? 'Scan completed. Report ready for review.' :
            job.status === 'error' ? (job.error || job.message) : (job.message || 'Analysis is running.');

        const completed = Math.max(0, Math.min(4, Number(job.steps_completed) || 0));
        const segments = document.createElement('div');
        segments.className = 'ah-job__segments';
        segments.setAttribute('role', 'progressbar');
        segments.setAttribute('aria-label', 'Completed scan stages');
        segments.setAttribute('aria-valuemin', '0');
        segments.setAttribute('aria-valuemax', '4');
        segments.setAttribute('aria-valuenow', String(completed));
        for (let i = 0; i < 4; i++) {
            const segment = document.createElement('span');
            if (i < completed) segment.classList.add('is-complete');
            if (i === completed && job.status === 'running') segment.classList.add('is-current');
            segments.appendChild(segment);
        }

        const foot = document.createElement('div');
        foot.className = 'ah-job__foot';
        const detail = document.createElement('span');
        if (job.status === 'completed') {
            detail.textContent = '4 of 4 stages complete';
        } else if (job.status === 'error') {
            detail.textContent = completed + ' of 4 stages complete';
        } else if (job.status === 'queued') {
            detail.textContent = 'Waiting for the worker · 4 stages remaining';
        } else {
            detail.textContent = completed + ' of 4 complete · ' + (4 - completed) + ' remaining';
            if (job.stage_elapsed_seconds != null) detail.textContent += ' · ' + duration(job.stage_elapsed_seconds) + ' in this stage';
            if ((job.stage === 'decompiling' || job.stage === 'decompiling_simple' || job.stage === 'decompiling_dex') &&
                job.jadx_progress && job.jadx_progress.total > 0) {
                detail.textContent += ' · JADX ' + job.jadx_progress.done + '/' + job.jadx_progress.total + ' (' + job.jadx_progress.percent + '%)';
                const idle = Date.now() / 1000 - job.jadx_progress.observed_at;
                if (idle > 60) detail.textContent += ' · no advance for ' + duration(idle);
            } else if (job.stage === 'decompiling' && job.files_written != null) {
                detail.textContent += ' · ' + job.files_written + ' files written';
            }
        }
        foot.appendChild(detail);
        if (job.status === 'completed' && job.report_url) {
            const link = document.createElement('a');
            link.href = job.report_url;
            link.textContent = 'View report';
            foot.appendChild(link);
        }
        item.append(top, message, segments, foot);
        return item;
    }

    async function refresh() {
        try {
            const response = await fetch('/api/running-scans', { cache: 'no-store' });
            if (!response.ok) throw new Error('Status service unavailable');
            const data = await response.json();
            const jobs = Object.values(data).filter(job => job && typeof job === 'object')
                .filter(job => job.status === 'queued' || job.status === 'running' ||
                    (job.completed_at && Date.now() / 1000 - job.completed_at < 180));
            jobs.sort((a, b) => (b.submitted_at || 0) - (a.submitted_at || 0));
            const fingerprint = JSON.stringify(jobs);
            if (count) count.textContent = jobs.length ? '· ' + jobs.length + ' recent' : '';
            if (fingerprint !== lastFingerprint) {
                list.replaceChildren(...jobs.slice(0, 3).map(makeJob));
                lastFingerprint = fingerprint;
            }
            dock.classList.toggle('d-none', jobs.length === 0);
            document.body.classList.toggle('has-scan-dock', jobs.length > 0);
        } catch (error) {
            if (lastFingerprint) {
                dock.classList.remove('d-none');
                document.body.classList.add('has-scan-dock');
                list.replaceChildren();
                const notice = document.createElement('p');
                notice.className = 'ah-job__message';
                notice.textContent = 'Scan status is temporarily unavailable. Refresh this page to reconnect.';
                list.appendChild(notice);
                lastFingerprint = '';
            }
        }
    }

    refresh();
    window.setInterval(refresh, 3000);
    document.addEventListener('visibilitychange', function () { if (!document.hidden) refresh(); });
})();
