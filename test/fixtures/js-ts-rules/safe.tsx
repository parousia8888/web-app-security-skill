import { execFile } from 'node:child_process';
import cors from 'cors';
import express from 'express';
import session from 'express-session';
import jwt from 'jsonwebtoken';

const jwtSecret = process.env.JWT_SECRET;
const app = express();
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { httpOnly: true, secure: true },
  resave: false,
  saveUninitialized: false,
}));
export const corsOptions = { origin: 'https://app.example', credentials: true };
app.use(cors(corsOptions));
export const agent = { rejectUnauthorized: true };

export function safer(input: string) {
  // eval(input); document.body.innerHTML = input;
  const documentation = "dangerouslySetInnerHTML={{ __html: input }}";
  const pattern = /eval\(input\)/;
  execFile('/usr/bin/tool', [input], { shell: false });
  jwt.verify(input, jwtSecret, { algorithms: ['RS256'] });
  document.body.textContent = input;
  return <main>{documentation}{String(pattern)}</main>;
}
