package main

/*
	What we need (file)
	- name of file
	- extension
	- original path
	- creation date, modified date
	Exif data
	- Model (APN)
	- DateTime
	- DateTimeDigitized
	- DateTimeOriginal
	- ExifVersion
	Depulication info
	- exif content hash
	- ?
*/

// Don't remove golang.org/x/sys/windows

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/rwcarlsen/goexif/exif"

	_ "github.com/mattn/go-sqlite3"
)

// MIME type equivalent https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
var contentTypeByExtension = map[string]string{
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".jfif": "image/jpeg",
	".png":  "image/png",
	".gif":  "image/gif",
	".bmp":  "image/bmp",
	".tif":  "image/tiff",
	".tiff": "image/tiff",
	".webp": "image/webp",
	".3gp":  "video/3gpp",
	".mp2":  "video/mp2",
	".mp4":  "video/mp4",
	".m4v":  "video/x-m4v",
	".mpeg": "video/mpeg",
	".mpg":  "video/mpeg",
	".avi":  "video/x-msvideo",
	".mov":  "video/quicktime",
	".webm": "video/webm",
	".h261": "video/h261",
	".h263": "video/h263",
	".h264": "video/h264",
	".wm":   "video/x-ms-wm",
	".wmv":  "video/x-ms-wmv",
	".ts":   "video/mp2t",
	".ogv":  "video/ogg",
}

func getFileDates(completeFilePath string) (creationDate, modificationDate time.Time, err error) {

	// Get file information
	fileInfo, err := os.Stat(completeFilePath)
	if err != nil {
		return
	}

	// Get that f... creation date
	// https://stackoverflow.com/questions/56063685/how-to-handle-fileinfo-sys-on-different-operating-systems
	creationDate = time.Unix(0, fileInfo.Sys().(*syscall.Win32FileAttributeData).CreationTime.Nanoseconds())
	modificationDate = fileInfo.ModTime()

	return
}

func visitFile(completeFilePath string, info os.FileInfo, err error) error {

	var exifDate time.Time

	// Basics

	// Get the filename
	fileName := filepath.Base(completeFilePath)

	// Get the path without the file
	filePathNoName := filepath.Dir(completeFilePath)

	// Get the extension
	fileExtension := filepath.Ext(fileName)

	// Parsing file info

	if err != nil {
		fmt.Println(err) // Can't walk here,
		return nil       // but continue walking elsewhere
	}
	if info.IsDir() {
		return nil // Not a file. Ignore.
	}

	// OS Dates
	creationDate, modificationDate, err := getFileDates(completeFilePath)
	if err != nil {
		log.Fatal(err)
	}

	// Determine file type
	contentType := contentTypeByExtension[strings.ToLower(filepath.Ext(info.Name()))]

	// If it's a picture or video, try reading EXIF data
	if strings.HasPrefix(contentType, "image/") || strings.HasPrefix(contentType, "video/") {

		// Open the file
		file, err := os.Open(completeFilePath)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return err
		}
		defer file.Close()

		// Exif Data

		exifData, err := exif.Decode(file)

		if err == nil {
			//var jsonExif []byte

			exifDate, _ = exifData.DateTime()

			//lat, long, _ := exifData.LatLong()
		}

		/*fmt.Printf("Name:       %s\nfilePath:   %s\nSize:       %d bytes\nType:       %s\nCDate:      %v\nMDate:      %v\nExifDate:   %v\n", info.Name(), filePath, info.Size(), contentType,
		creationDate.Format("2006-01-02 15:04:05"), modificationDate.Format("2006-01-02 15:04:05"), exifDate.Format("2006-01-02 15:04:05"))*/
		fmt.Printf("%s;%s;%s;%s;%d;%s;%v;%v;%v\n", info.Name(), fileName, fileExtension, filePathNoName, info.Size(), contentType, creationDate.Format("2006-01-02 15:04:05"), modificationDate.Format("2006-01-02 15:04:05"), exifDate.Format("2006-01-02 15:04:05"))
	}

	return nil
}

func main() {

	// Usage & Arguments (parameters)

	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <directory filePath>")
		return
	}

	if runtime.GOOS == "windows" {

		dirfilePath := os.Args[1]

		// Walk through the path, to look for all pics & videos

		err := filepath.Walk(dirfilePath, visitFile)
		if err != nil {
			fmt.Printf("Error walking the filePath: %v\n", err)
		}
	} else {
		fmt.Println("Runs only under Windows (due to specific creation date handling)")
	}

	// Open a connection to the SQLite database
	db, err := sql.Open("sqlite3", "data.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create the table if it doesn't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS items (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT,
			price REAL
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()
}
