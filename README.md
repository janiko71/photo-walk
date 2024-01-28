# photo-walk

Based on https://github.com/janiko71/sd-transfert and https://github.com/janiko71/duplicates-walk.

The idea is to place all your images (images or video files actually) into a "target" folder, containing imported images without duplicates. The comparison is not made with the files present in the "target" folder but with a historical database which keeps track of all the images already imported.

For what? To prevent the import of files that you intentionally deleted. Then you can imports pics, delete the unneeded ones, and re-import again pictures into the target folder if you don't remember if it was already done or not. 

## Actions (argument)

- 'read-target' : Reads all the files in the target (destination) folder(s) and add them into the DB.  
- 'read-source' : Only reads the source folders and lists what would be copied
- 'testcopy' : Copies the files in a false target folder, does not add them into the DB
- 'import' : Imports the files, puts them into the DB

After 'read', files may exists in the DB without being copied. When copying, check if it exists and log. There's a log file for every import.

## Configuration file example

```
[directories]
target=
sources=
trash=trash

[log]
level=INFO
file=app.log

[db]
name=photo-walk.db
```