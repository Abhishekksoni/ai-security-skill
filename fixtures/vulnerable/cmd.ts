// INJ-002: OS Command Injection
import { exec } from 'child_process';

export function backupFiles(req: any) {
  const filename = req.query.filename;
  
  // VULNERABLE: Direct command concatenation executed in system shell
  exec(`tar -czf backups/backup.tar.gz uploads/${filename}`, (err, stdout) => {
    console.log(stdout);
  });
}
