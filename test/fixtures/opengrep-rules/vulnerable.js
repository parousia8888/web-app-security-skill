import childProcess from 'node:child_process';
import fs from 'node:fs';
import database from './database.js';

export async function runReport(req, res) {
  const command = req.query.command;
  childProcess.exec(command);
  const search = req.query.search;
  database.query(`SELECT * FROM reports WHERE name = '${search}'`);
  const destination = req.query.destination;
  await fetch(destination);
  const reportPath = req.query.path;
  fs.readFileSync(reportPath, 'utf8');
  const next = req.query.next;
  res.redirect(next);
}
