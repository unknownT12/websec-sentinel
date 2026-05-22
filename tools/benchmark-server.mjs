import http from 'node:http';
const port = Number(process.env.PORT || 49210);
const html = (body, script='') => `<!doctype html><html><head><title>Sentinel Benchmark</title><script src="/spa.js"></script>${script}</head><body>${body}</body></html>`;
const roleFromCookie = (req) => /role=admin/.test(req.headers.cookie || '') ? 'admin' : /role=lecturer/.test(req.headers.cookie || '') ? 'lecturer' : /role=student/.test(req.headers.cookie || '') ? 'student' : 'anonymous';
const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  const role = roleFromCookie(req);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (url.pathname === '/login') {
    res.setHeader('Content-Type', 'text/html');
    res.end(html(`<h1>Login</h1><form method="post" action="/session"><input name="email" type="email"><input name="password" type="password"><input name="csrf_token" value="bench"><button type="submit">Login</button></form><a href="/dashboard">Dashboard</a><a href="/search?q=test">Search</a><a href="/redirect?next=/dashboard">Redirect</a>`));
    return;
  }
  if (url.pathname === '/session') {
    res.statusCode = 302; res.setHeader('Set-Cookie', 'bench_session=abc; HttpOnly; SameSite=Lax'); res.setHeader('Location', '/dashboard'); res.end(); return;
  }
  if (url.pathname === '/dashboard') {
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Set-Cookie', 'bench_session=abc; HttpOnly; SameSite=Lax');
    res.end(html(`<h1>Dashboard</h1><p>role=${role}</p><nav><a href="/student/123?studentId=123&courseId=77">Student</a><a href="/admin/users">Admin</a><a href="/api/profile?studentId=123">API</a><a href="/reflect?q=hello">Reflect</a><a href="/redirect?next=/dashboard">Redirect</a><a href="/error?debug=true">Error</a></nav><form method="post" action="/profile/update"><input name="displayName"><input name="csrf_token" value="bench"><button type="submit">Save</button></form>`));
    return;
  }
  if (url.pathname === '/student/123') { res.setHeader('Content-Type', 'text/html'); res.end(html(`<h1>Student Record</h1><p>studentId=${url.searchParams.get('studentId')}</p><a href="/download/report.pdf">Report</a>`)); return; }
  if (url.pathname === '/admin/users') { res.setHeader('Content-Type', 'text/html'); res.end(html(`<h1>Admin Users</h1><p>Visible to role=${role}</p><table><tr><td>redacted@example.test</td></tr></table>`)); return; }
  if (url.pathname === '/api/profile') { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ studentId: url.searchParams.get('studentId'), email: 'redacted@example.test', role })); return; }
  if (url.pathname === '/reflect' || url.pathname === '/search') { res.setHeader('Content-Type', 'text/html'); res.end(html(`<h1>Search</h1><form action="/search"><input name="q"></form><p>${String(url.searchParams.get('q') || '')}</p>`)); return; }
  if (url.pathname === '/redirect') { res.statusCode = 302; res.setHeader('Location', String(url.searchParams.get('next') || '/dashboard')); res.end(); return; }
  if (url.pathname === '/error') { res.statusCode = 500; res.setHeader('Content-Type', 'text/html'); res.end(html(`<h1>Exception</h1><pre>Traceback: Error at BenchmarkController.line42 SQL syntax near SELECT * FROM users</pre>`)); return; }
  if (url.pathname === '/spa.js') { res.setHeader('Content-Type', 'application/javascript'); res.end(`window.__routes=['/admin/users','/account/reset','/api/grades?studentId=123','/search?q=spa','/redirect?next=/dashboard','/error?debug=true'];`); return; }
  if (url.pathname === '/robots.txt') { res.setHeader('Content-Type', 'text/plain'); res.end(`Allow: /dashboard\nSitemap: http://localhost:${port}/sitemap.xml\n`); return; }
  if (url.pathname === '/sitemap.xml') { res.setHeader('Content-Type', 'application/xml'); res.end(`<urlset><url><loc>http://localhost:${port}/dashboard</loc></url><url><loc>http://localhost:${port}/search?q=sitemap</loc></url><url><loc>http://localhost:${port}/redirect?next=/dashboard</loc></url><url><loc>http://localhost:${port}/error?debug=true</loc></url></urlset>`); return; }
  res.statusCode = 404; res.setHeader('Content-Type', 'text/html'); res.end(html('not found'));
});
server.listen(port, '127.0.0.1', () => console.log(`benchmark fixture listening on 127.0.0.1:${port}`));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
