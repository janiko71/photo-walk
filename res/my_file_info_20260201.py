class MyFileInfo:

    def __init__(self, fid=None, filename=None, extension=None, mime_type=None, original_path=None, dest_path=None, 
                    creation_date=None, creation_date_short=None, modify_date=None, filename_date=None, folder_date=None, file_hash=None, exif_date=None, 
                    exif_content=None, exif_hash=None, size=None, trt_date=None):
            
            self.fid = fid
            self.filename = filename
            self.file_extension = extension
            self.mime_type = mime_type
            self.original_path = original_path
            self.dest_path = dest_path
            self.creation_date = creation_date
            self.creation_date_short = creation_date_short
            self.modify_date = modify_date
            self.filename_date = filename_date
            self.folder_date = folder_date
            self.file_hash = file_hash
            self.exif_date = exif_date
            self.exif_content = exif_content
            self.exif_hash = exif_hash
            self.size = size
            self.trt_date = trt_date
            self.walk_type = "unknown"

    def afficher_infos(self):

        print(f"FID: {self.fid}")
        print(f"Filename: {self.filename}")
        print(f"Extension: {self.extension}")
        print(f"MIME Type: {self.mime_type}")
        print(f"Original Path: {self.original_path}")
        print(f"Destination Path: {self.dest_path}")
        print(f"Creation Date: {self.creation_date}")
        print(f"Creation Date (short): {self.creation_date_short}")
        print(f"Modify Date: {self.modify_date}")
        print(f"Filename Date: {self.filename_date}")
        print(f"Folder Date: {self.folder_date}")
        print(f"File Hash: {self.file_hash}")
        print(f"Exif Date: {self.exif_date}")
        print(f"Exif Content: {self.exif_content}")
        print(f"Exif Hash: {self.exif_hash}")
        print(f"Size: {self.size}")
        print(f"Traitement Date: {self.trt_date}")
        print(f"Type: {self.walk_type}")


