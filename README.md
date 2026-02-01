# photo-walk

Based on:
- https://github.com/janiko71/sd-transfert
- https://github.com/janiko71/duplicates-walk

## Overview

Photo-walk builds a **reference library** for photos and videos, without duplicates.  
It does **not** compare with the files currently present in the reference folder.  
Instead, it uses a **historical database** of all imported files.

Why? If you import files, delete the bad ones, then re-import later, you still want to avoid bringing in duplicates.  
This keeps your reference library clean, even across multiple imports and cleanups.

## How it works (short version)

- The DB stores hashes and metadata of everything you already imported.
- Any file, anywhere, is re-checked by hashing.
- If the hash is already in the DB, it is skipped.

## Commands

- `rebuild` : read all files from the reference folder(s) and add them into the DB  
- `read` : scan import sources and **show** what would be copied  
- `test` : copy to a test folder (no DB updates)  
- `import` : copy to reference + add to DB

After `read`, files may exist in the DB without being copied.  
Each run produces a log file.

## Typical usage

```bash
python photo-walk.py rebuild
python photo-walk.py read
python photo-walk.py test
python photo-walk.py import
```

## Configuration (config.ini)

```ini
[directories]
reference=
import_dirs=
trash=trash

[log]
level=INFO
file=app.log

[db]
name=photo-walk.db
```

## Notes

- Formats supportes: images (jpg, png, tif, webp...), RAW (arw, cr2, nef, raf...) et videos (mov, mp4, avi, ...).
- Le hash SHA-256 est utilise pour identifier un fichier, independamment de son nom ou de son emplacement.
- Les logs sont ecrits dans `./log/` avec un fichier par execution.

## Exemple de flux

```
[Sources] ---> read ---> (liste des fichiers a importer)
     |
     +------> test  ---> (copie en dossier de test, sans DB)
     |
     +------> import ---> [Reference] + [DB]

rebuild ---> [Reference] ---> (ajout en DB)
```
