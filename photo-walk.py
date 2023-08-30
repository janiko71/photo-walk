import os, io, sys
import shutil
import PIL.Image as PILimage
from datetime import datetime
from dateutil import parser
import re
import hashlib
import logging


# -------------------------------------------
#  Files extensions list
# -------------------------------------------

PICT_EXT_LIST = {".jpg", ".jpeg", ".jfif", ".bmp", ".gif", ".png", ".tif", ".tiff", ".webp"}
RAW_PICT_EXT_LIST = {".arw", ".cr2", ".cr3", ".crw", ".dcr", ".dcs", ".dng", ".drf", ".gpr", \
                     ".k25", ".kdc", ".mrw", ".nef", ".nrw", ".orf", ".pef", ".ptx", ".raf", \
                     ".raw", ".rw2", ".sr2", ".srf", ".srw", ".x3f"}
VIDEO_EXT_LIST = {".mpg", ".mp2", ".mpeg", ".mpe", ".mpv", ".mov", ".ogv", ".mp4", ".m4p", ".m4v", ".avi", ".ts", ".webm", ".wm", ".wmv", ".avchd"}

# -------------------------------------------
#  Log configuration
# -------------------------------------------

# create logger
logging.basicConfig(filename='app.log', level=logging.INFO)


    
# -------------------------------------------
def extract_date_from_filename(filename):
# -------------------------------------------

    # Define a regex pattern to capture dates in various formats
    date_pattern = r'(\d{4}-\d{2}-\d{2})|(\d{2}-\d{2}-\d{4})|(\d{2}/\d{2}/\d{4})|(\d{8}-\d{6})|(\d{8}[T_]\d{6})'

    # Search for the date pattern in the filename
    match = re.search(date_pattern, filename)

    if match:
        # Extract the matched date from the captured groups
        extracted_date = match.group(0).replace('_','-') # To prevent parsing errors
        
        # Parse the extracted date using dateutil.parser
        parsed_date = parser.parse(extracted_date)
        
        # Reformat the parsed date to "yyyy-mm-dd" format
        reformatted_date = parsed_date.strftime('%Y-%m-%d')
        
        return reformatted_date
    else:
        return None
    

# -------------------------------------------
def main():
# -------------------------------------------    

    basepath    = "test"
    target      = "copie"

    logging.info("Parsing " + basepath + " directory")

    os.chdir(basepath)

    for root, _, files in os.walk(".", topdown=True):

        for f_name in files:

            # File infos
            
            img_path = os.path.join(root, f_name)
            file_ext = os.path.splitext(img_path)[1].lower()
            fs = os.stat(img_path)
            file_creation_date = datetime.fromtimestamp(fs.st_ctime)
            extracted_date = extract_date_from_filename(f_name)
            file_creation_day = "{:04d}-{:02d}-{:02d}".format(file_creation_date.year, file_creation_date.month, file_creation_date.day)

            try:

                copy = False
                folder_date = None
                exif_date = None
                exif_hash = None
                
                if (file_ext in PICT_EXT_LIST):

                    # exif-like file

                    copy = True
                    
                    img = PILimage.open(img_path)
                    img_exif = img._getexif()
                    exif_date = img_exif.get(36867)
                    folder_date = exif_date[:10].replace(':','-')

                    img_exif_str = str(img_exif).encode('utf-8')
                    exif_hash = hashlib.sha256(img_exif_str).hexdigest()

                elif ((file_ext in RAW_PICT_EXT_LIST) or (file_ext in VIDEO_EXT_LIST)):
                    
                    # video or raw file

                    copy = True
                    if extracted_date:
                        folder_date = extracted_date
                    else:
                        folder_date = file_creation_day

                # Copying file

                if (copy):

                    # Destination folder (based on date)
                    
                    yr = folder_date[0:4]
                    dest_dt = "{:04d}-{:02d}-{:02d}".format(int(yr), int(folder_date[5:7]), int(folder_date[8:10]))

                    yr_path = target + os.sep + yr
                    pic_path = yr_path + os.sep + dest_dt + os.sep
                
                    output_extracted_date = extracted_date if extracted_date is not None else ""
                    output_exif_hash = exif_hash if exif_hash is not None else ""
                    logging.info("(1){:<10} (2){} (3){} (4){} (5){:<30} (6){}".format(output_extracted_date, file_creation_day, exif_date, folder_date, f_name[:30], output_exif_hash))

                    if not(os.path.exists(yr_path)):
                        str_log = f"Folder {yr_path} unkown, creating..."
                        logging.info(str_log)
                        os.makedirs(yr_path)
                        
                    if not(os.path.exists(pic_path)):
                        str_log = f"Folder {pic_path} unkown, creating..."
                        logging.info(str_log)
                        os.makedirs(pic_path)
                    
                    if not(os.path.exists(pic_path + f_name)):
                        str_log = f"Copying {img_path} --> {pic_path + f_name}"
                        logging.info(str_log)
                        print("{} --> {}".format(img_path, pic_path + f_name))
                        shutil.copy2(img_path, pic_path + f_name)
                
            except Exception as e:

                str_log = f"Error {str(e)} on {img_path}"
                logging.error(str_log)
                    
    logging.info("End of Parsing")


# -------------------------------------------
#  main call
# -------------------------------------------

if __name__ == '__main__':
    main()