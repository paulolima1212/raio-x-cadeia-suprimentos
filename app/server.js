// App brinquedo: "Raio-X" responde na porta 8080
require('http').createServer((_, res) => res.end('Raio-X da Cadeia de Suprimentos: OK\n')).listen(8080);
