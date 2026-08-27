// INJ-002: OS Command Injection
import { spawn } from 'child_process';

export function backupFiles(req: any) {
  const filename = req.query.filename;
  
  // SECURE: Spawn execution binary with strict arguments array and shell disabled
  spawn('tar', ['-czf', 'backups/backup.tar.gz', `uploads/${filename}`], {
    shell: false
  });
}
