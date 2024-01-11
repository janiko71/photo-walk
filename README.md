# photo-walk

Based on https://github.com/janiko71/sd-transfert and https://github.com/janiko71/duplicates-walk.

The idea is to place all your images (images or video files actually) into a "target" folder, containing imported images without duplicates. The comparison is not made with the files present in the "target" folder but with a historical database which keeps track of all the images.

For what? To prevent the import of files that you intentionally deleted. Then you can imports pics, delete the unneeded ones, and re-import again pictures into the target folder if you don't remember if it was already done or not. 

## Actions (argument)

- 'reset' : Delete DB and then read. All other options update the DB without erasing it. 
- 'read' : Only read the target folder and the source folders, and fill the DB 
- 'testcopy' : Copy the files in a false target folder, do not mark files as imported (to test the copy or whatever)
- 'import' : Imports the files, marks them as imported, updates dest path

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