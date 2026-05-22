import http from 'node:http';

const port = Number(process.env.PORT || 48181);
const html = (body) => `<!doctype html><html><head><title>Fixture</title><script src="/app.js"></script></head><body>${body}</body></html>`;

const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (url.pathname === '/login') {
    res.setHeader('Content-Type', 'text/html');
    res.end(html(`<form method="post" action="/session"><input name="email" type="email"><input name="password" type="password"><input name="csrf_token" value="fixture"></form><a href="/dashboard">Dashboard</a>`));
    return;
  }
  if (url.pathname === '/dashboard') {
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Set-Cookie', 'fixture_session=abc; HttpOnly; Secure; SameSite=Lax');
    res.end(html(`<h1>Dashboard</h1><a href="/student/123?courseId=77">Student</a><a href="/api/profile?studentId=123">API</a><form method="get" action="/search"><input name="q"><input name="studentId"></form><form method="post" action="/profile/update"><input name="displayName"><input name="csrf_token" value="fixture"></form>`));
    return;
  }
  if (url.pathname.startsWith('/student/')) {
    res.setHeader('Content-Type', 'text/html');
    res.end(html(`<h1>Student Record</h1><a href="/download/report.pdf">Report</a>`));
    return;
  }
  if (url.pathname === '/api/profile') {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ studentId: url.searchParams.get('studentId'), email: 'redacted@example.test', role: 'student' }));
    return;
  }
  if (url.pathname === '/app.js') {
    res.setHeader('Content-Type', 'application/javascript');
    res.end(`const routes=['/admin/users','/account/reset','/api/grades?studentId=123']; function go(x){ location.href=x }`);
    return;
  }
  if (url.pathname === '/robots.txt') {
    res.setHeader('Content-Type', 'text/plain');
    res.end('Allow: /dashboard\nSitemap: http://localhost:' + port + '/sitemap.xml\n');
    return;
  }
  if (url.pathname === '/sitemap.xml') {
    res.setHeader('Content-Type', 'application/xml');
    res.end('<urlset><url><loc>http://localhost:' + port + '/dashboard</loc></url></urlset>');
    return;
  }
  res.statusCode = 404;
  res.setHeader('Content-Type', 'text/html');
  res.end(html('not found'));
});

server.listen(port, '127.0.0.1', () => console.log(`selftest fixture listening on 127.0.0.1:${port}`));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
