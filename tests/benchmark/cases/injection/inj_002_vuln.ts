import { exec } from 'child_process';

export function backupFiles(filename: string) {
  // VULNERABLE: OS Command Injection via shell template literal interpolation
  exec(`tar -czf backups/backup.tar.gz uploads/${filename}`, (err, stdout, stderr) => {
    if (err) console.error(err);
  });
}
