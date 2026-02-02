# photo-walk
Pics &amp; videos importation, sorted by date, without duplication

Based on https://github.com/janiko71/sd-transfert and https://github.com/janiko71/duplicates-walk.

## Installation
```
$ setx CGO_ENABLED 1
$ go mod tidy
$ go get golang.org/x/sys/windows
$ -- go mod download golang.org/x/sys
$ go install golang.org/x/sys/windows
```
CGO is needed to use the sqlite3 C-libraries. Don't re-run go mod tidy unless you know what you're doing!

==> TOO COMPLEX TO BUILD with Windows OS/syscall and SQLITE3. 