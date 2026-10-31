const PYODIDE = 'https://cdn.jsdelivr.net/pyodide/v0.27.7/full/';
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const INSTALL_HINT = 'You can still run it locally with pip install ci-agent-audit.';

const examples = JSON.parse(document.getElementById('examples').textContent);
const source = document.getElementById('source');
const gutter = document.getElementById('gutter');
const marks = document.getElementById('marks');
const report = document.getElementById('report');
const status = document.getElementById('status');
const fileLabel = document.getElementById('file');
const scanButton = document.getElementById('scan');
const tabs = document.getElementById('tabs');

const element = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

const syncScroll = () => {
  gutter.scrollTop = source.scrollTop;
  marks.scrollTop = source.scrollTop;
};

const renderGutter = () => {
  const count = source.value.split('\n').length;
  gutter.textContent = Array.from({ length: count }, (_, index) => index + 1).join('\n');
  syncScroll();
};

const renderMarks = (findings) => {
  const worst = new Map();
  [...findings].reverse().forEach((finding) => worst.set(finding.line, finding.severity));
  marks.replaceChildren(...[...worst].map(([line, severity]) => {
    const mark = element('div', `mark ${severity}`);
    mark.style.setProperty('--n', line);
    return mark;
  }));
  // Keeps the strips scrolling with long files
  const spacer = element('div');
  spacer.style.height = `${source.scrollHeight}px`;
  marks.append(spacer);
  syncScroll();
};

const jumpToLine = (line) => {
  const lines = source.value.split('\n');
  const start = lines.slice(0, line - 1).reduce((total, text) => total + text.length + 1, 0);
  source.focus({ preventScroll: true });
  source.setSelectionRange(start, start + (lines[line - 1] || '').length);
  const row = parseFloat(getComputedStyle(source).lineHeight);
  source.scrollTop = Math.max(0, (line - 3) * row);
  if (matchMedia('(max-width: 860px)').matches) source.scrollIntoView({ block: 'center' });
};

const renderFinding = (finding) => {
  const article = element('article', 'finding');
  const header = element('header');
  const rule = element('a', '', finding.rule_id);
  rule.href = `#${finding.rule_id}`;
  const jump = element('button', 'jump', `Line ${finding.line}`);
  jump.type = 'button';
  jump.addEventListener('click', () => jumpToLine(finding.line));
  header.append(element('span', `tag ${finding.severity}`, finding.severity.toUpperCase()), rule, jump);

  const details = element('details');
  details.append(element('summary', '', 'How to fix it'), element('p', '', finding.remediation));
  article.append(header, element('p', '', finding.message), details);
  return article;
};

const renderVerdict = (result) => {
  const count = result.findings.length;
  const totals = SEVERITIES
    .map((severity) => [result.findings.filter((finding) => finding.severity === severity).length, severity])
    .filter(([total]) => total);
  const failing = result.findings.some((finding) => ['critical', 'high'].includes(finding.severity));
  const stamp = failing ? ['fails', 'Fails'] : count ? ['passes', 'Passes'] : ['clean', 'Clean'];
  let summary = "A clean report doesn't prove a workflow is safe.";
  if (count) summary = totals.map(([total, severity]) => `${total} ${severity}`).join(', ');
  if (count && !failing) summary += '. Below the default CI failure level.';
  if (result.ignored) summary += ` ${result.ignored} ignored by a comment.`;

  const verdict = element('div', 'verdict');
  const title = count ? `${count} issue${count === 1 ? '' : 's'} found` : 'No issues found';
  verdict.append(
    element('p', 'label kind', result.kind),
    element('h2', '', title),
    element('span', `stamp ${stamp[0]}`, stamp[1]),
    element('p', '', summary),
  );
  return verdict;
};

const renderResult = (result) => {
  report.classList.remove('stale');
  if (result.error) {
    renderMarks([]);
    const verdict = element('div', 'verdict');
    verdict.append(element('p', 'label kind', 'Not scanned'), element('h2', '', "Couldn't scan this"), element('p', '', result.error));
    report.replaceChildren(verdict);
    return;
  }
  report.replaceChildren(renderVerdict(result), ...result.findings.map(renderFinding));
  report.scrollTop = 0;
  renderMarks(result.findings);
};

const renderEmpty = (title, text) => {
  report.classList.remove('stale');
  const verdict = element('div', 'verdict');
  verdict.append(element('p', 'label kind', 'Ready'), element('h2', '', title), element('p', '', text));
  report.replaceChildren(verdict);
};

let engine;
const loadEngine = () => {
  engine ??= (async () => {
    await new Promise((resolve, reject) => {
      const script = element('script');
      script.src = `${PYODIDE}pyodide.js`;
      script.onload = resolve;
      script.onerror = reject;
      document.head.append(script);
    });
    const python = await loadPyodide({ indexURL: PYODIDE });
    await python.loadPackage('pyyaml', { messageCallback: () => {} });
    const scanner = await fetch('scanner.zip');
    if (!scanner.ok) throw new Error('scanner.zip is missing');
    python.unpackArchive(await scanner.arrayBuffer(), 'zip', { extractDir: '/home/pyodide/scanner' });
    return python.runPython(`
import sys
sys.path.insert(0, '/home/pyodide/scanner')
from site_scan import scan_text
scan_text
`);
  })().catch((error) => {
    engine = undefined;
    throw error;
  });
  return engine;
};

const scan = async () => {
  const text = source.value;
  status.textContent = '';
  if (!text.trim()) {
    renderEmpty('Nothing to scan', 'Paste a GitHub Actions or GitLab CI file on this side.');
    return;
  }
  const known = examples.find((example) => example.text === text);
  if (known) {
    renderResult(known.result);
    return;
  }

  scanButton.disabled = true;
  status.textContent = engine ? 'Scanning…' : 'Loading the scanner. This is about 6 MB the first time.';
  try {
    const scanText = await loadEngine();
    const result = JSON.parse(scanText(text));
    if (source.value === text) renderResult(result);
    status.textContent = source.value === text ? '' : 'The workflow changed. Scan again.';
  } catch (error) {
    console.error(error);
    status.textContent = `Couldn't load the scanner. ${INSTALL_HINT}`;
  } finally {
    scanButton.disabled = false;
  }
};

const selectTab = (slug) => {
  tabs.querySelectorAll('button').forEach((button) => button.setAttribute('aria-pressed', button.dataset.slug === slug));
};

const showExample = (example) => {
  source.value = example.text;
  source.scrollTop = 0;
  source.scrollLeft = 0;
  fileLabel.textContent = example.file;
  status.textContent = '';
  selectTab(example.slug);
  renderGutter();
  renderResult(example.result);
};

examples.forEach((example) => {
  const button = element('button', '', example.label);
  button.type = 'button';
  button.dataset.slug = example.slug;
  button.addEventListener('click', () => showExample(example));
  tabs.append(button);
});

source.addEventListener('scroll', syncScroll);
source.addEventListener('input', () => {
  renderGutter();
  renderMarks([]);
  report.classList.add('stale');
  fileLabel.textContent = 'your-workflow.yml';
  status.textContent = 'Press Scan to check your changes.';
  selectTab('');
});
source.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) scan();
});
scanButton.addEventListener('click', scan);
document.getElementById('clear').addEventListener('click', () => {
  source.value = '';
  fileLabel.textContent = 'your-workflow.yml';
  status.textContent = '';
  selectTab('');
  renderGutter();
  renderMarks([]);
  renderEmpty('Paste your workflow', 'It runs here in your browser. Nothing is uploaded.');
  source.focus();
});

document.querySelectorAll('.copy').forEach((button) => button.addEventListener('click', async () => {
  const from = button.dataset.copyFrom;
  const text = from ? document.getElementById(from).textContent : button.dataset.copy;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied';
  } catch {
    button.textContent = 'Select it';
    getSelection().selectAllChildren(button.parentElement.querySelector('code'));
  }
  setTimeout(() => { button.textContent = 'Copy'; }, 1600);
}));

window.addEventListener('resize', syncScroll);
showExample(examples[0]);
