import express from 'express';
import { join } from 'path';
import { json, urlencoded } from 'body-parser';
import cors from 'cors';
import { strategy } from './helpers/middleware';

require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});

app.enable('trust proxy');
app.disable('x-powered-by');

app.use(json({ limit: '20mb' }));
app.use(urlencoded({ limit: '20mb', extended: false }));
app.use(cors());
app.use(strategy);
app.use(express.static(join(__dirname, 'public')));

app.use('/api', require('./routes/api').default);

app.get('/status', (req, res) => {
  res.json({
    status: "ok",
    node: process.env.BROADCAST_URL,
    account: process.env.BROADCASTER_USERNAME
  })
});

app.get('/*', (req, res) => {
  res.redirect('https://www.hivesso.com');
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
