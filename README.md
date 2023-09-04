# photo-walk

Based on https://github.com/janiko71/sd-transfert and https://github.com/janiko71/duplicates-walk.

## Actions (argument)

- 'new' : Delete DB and then read. All other options update the DB without erasing it. 
- 'read' : Only read the destination folder and the source folders 
- 'copy' : Copy the files in a false destination folder, do not mark files as imported (to test the copy or whatever)
- 'import' : Imports the files, marks them as imported, updates dest path

After 'read', files may exists in the DB without being copied. When copying, check if it exists and log. 

## Configuration file example

```
[directories]
destination=
sources=
trash=trash

[log]
level=INFO
file=app.log

[db]
name=photo-walk.db
```