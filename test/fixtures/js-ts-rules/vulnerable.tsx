import { exec as runCommand, spawn } from 'node:child_process';
import cors from 'cors';
import express from 'express';
import session from 'express-session';
import jwt from 'jsonwebtoken';

const jwtSecret = 'fixture-value-never-use-12345';
const app = express();
app.use(session({
  secret: 'fixture-session-secret-never-deploy',
  cookie: { httpOnly: false, secure: false },
  resave: false,
  saveUninitialized: false,
}));
export const corsOptions = { origin: '*', credentials: true };
app.use(cors(corsOptions));
export const agent = { rejectUnauthorized: false };

export function unsafe(input: string) {
  eval(input);
  runCommand(input);
  spawn('tool', [input], { shell: true });
  jwt.verify(input, jwtSecret, { algorithms: ['none'] });
  document.body.innerHTML = input;
  document.write(input);
  return <main dangerouslySetInnerHTML={{ __html: input }} />;
}
