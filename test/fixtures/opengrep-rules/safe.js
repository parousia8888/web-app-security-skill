import { execFile } from 'node:child_process';
import fs from 'node:fs';
import database from './database.js';

export async function runReport(req, res) {
  execFile('/usr/bin/report', ['--format', 'json']);
  const search = req.query.search;
  database.query('SELECT * FROM reports WHERE name = ?', [search]);
  if (req.query.destination === 'status') await fetch('https://status.example.invalid/health');
  if (req.query.path === 'daily') fs.readFileSync('/srv/reports/daily.json', 'utf8');
  if (req.query.next === 'docs') {
    res.redirect('/docs');
    return;
  }
  res.redirect('/');
}
