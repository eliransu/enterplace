// Under each page title: Copy page (the page as Markdown), Open in Claude and Open in ChatGPT, each with the address of
// the page's Markdown twin, so a coding agent or a chat reads the page as text.
(function () {
	var title = document.querySelector('main h1');
	if (!title || document.querySelector('.enterplace-agent')) return;
	var path = location.pathname.replace(/\/$/, '');
	var md = location.origin + (path === '' ? '/index' : path) + '.md';
	var ask = 'Read ' + md + ' and help me with it. More Enterplace docs as Markdown: ' + location.origin + '/llms.txt';
	var bar = document.createElement('div');
	bar.className = 'enterplace-agent';
	var copy = document.createElement('button');
	copy.type = 'button';
	copy.textContent = 'Copy page';
	copy.setAttribute('data-md', md);
	copy.addEventListener('click', function () {
		fetch(md).then(function (r) { return r.text(); }).then(function (text) {
			return navigator.clipboard.writeText(text);
		}).then(function () { copy.textContent = 'Copied'; }).catch(function () { copy.textContent = 'Copy failed'; });
	});
	bar.appendChild(copy);
	[['Open in Claude', 'https://claude.ai/new?q='], ['Open in ChatGPT', 'https://chatgpt.com/?q=']].forEach(function (pair) {
		var a = document.createElement('a');
		a.textContent = pair[0];
		a.href = pair[1] + encodeURIComponent(ask);
		a.target = '_blank';
		a.rel = 'noopener';
		bar.appendChild(a);
	});
	var md_link = document.createElement('a');
	md_link.textContent = 'Markdown';
	md_link.href = md;
	bar.appendChild(md_link);
	title.insertAdjacentElement('afterend', bar);
})();
