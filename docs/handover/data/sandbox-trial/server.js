const http = require('http');
const { summarize } = require('./app');

const port = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
  } else if (req.url === '/summary') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(summarize([1, 2, 3, 4])));
  } else {
    res.writeHead(404);
    res.end();
  }
});

server.listen(port, () => console.log(`listening on ${port}`));
