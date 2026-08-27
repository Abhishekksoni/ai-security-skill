import { execFile } from 'child_process';

export function backupFiles(filename: string) {
  // SECURE: Use execFile to pass variables as isolated array arguments without shell interpretation
  execFile('tar', ['-czf', 'backups/backup.tar.gz', `uploads/${filename}`], (err, stdout, stderr) => {
    if (err) console.error(err);
  });
}
