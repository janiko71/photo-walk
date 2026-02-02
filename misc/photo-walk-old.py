import os
import io
import sys
import re
import hashlib
import logging
import sqlite3
import shutil

from datetime import datetime
from dateutil import parser

import PIL.Image as PILimage

import utils


# -------------------------------------------
#  Datas for images/videos
# -------------------------------------------
#
# Filename, extension, mime file_type, filepath, creation date, modify date, filename date, file hash?
# exif date, exif infos, exif hash, imported, excluded
#

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

#
# ---> Some inits
#

db      = utils.db_name
restart = False


#
#    ====================================================================
#     Database creation
#    ====================================================================
#

def db_create(db):

    """

        Creates the database tables (unconditionnally).

        Args:
            db (text): Name of the file used for storing sqlite3 database

        Returns:
            cnx (sqlite3.Connection): Connection object (bound to the file _filename_)
    """

    cnx = sqlite3.connect(db)
    #cnx = sqlite3.connect(':memory:') ==> in-memory for sqlite3 is not really faster 
    logging.info("Creating database %s", db)

    #
    # ---> Dropping old tables
    #

    try:

        # Drop all tables

        cnx.execute("DROP TABLE filelist")
        cnx.execute("DROP TABLE params")
        logging.info("Old database deleted.")

    except sqlite3.OperationalError:

        # Exception means no old database

        logging.info("No old database.")

    #
    # ---> Let's create the table used for storing files information
    #
    # Filename, extension, mime file_type, filepath, creation date, modify date, filename date, file hash?
    # exif date, exif infos, exif hash, imported, excluded
    cnx.execute("CREATE TABLE filelist (\
                    fid INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, \
                    filename TINYTEXT, \
                    extension CHAR(30), \
                    mime_type CHAR(30), \
                    filepath VARCHAR(4096), \
                    creation_date TEXT, \
                    modify_date TEXT, \
                    filename_date TEXT, \
                    file_hash CHAR(256), \
                    exif_date TEXT, \
                    exif_content TEXT, \
                    exif_hash CHAR(256), \
                    size BIGINT, \
                    protected BOOL, \
                    marked_as_imported BOOL, \
                    marked_to_delete BOOL) \
                ")
    logging.info("Database successfully created")

    # ---> Some useful indexes to speed up the processing

    cnx.execute("CREATE INDEX index_filepath ON filelist (filepath, filename)")
    cnx.execute("CREATE INDEX index_exif_hash ON filelist (exif_hash)")
    cnx.execute("CREATE INDEX index_file_hash ON filelist (file_hash)")
    logging.info("Indexes successfully created")

    #
    # ---> Params table used to store infomation about the process and restart steps.
    #
    
    cnx.execute("CREATE TABLE params(\
                    key TINYTEXT,\
                    value TEXT)\
                ")

    # --- > Default values

    cnx.execute("INSERT INTO params VALUES ('last_path','')")
    cnx.execute("INSERT INTO params VALUES ('last_file','')")
    logging.info("Table params created")

    cnx.commit()

    logging.info("Database %s and tables created", db)

    return cnx


#
#    ====================================================================
#     Database connexion
#    ====================================================================
#

def db_connect(db, restart = False):

    """

        Connects to the file which will be used for the sqlite3 database. If needed (= if you start a new search or if you've asked for a restart manually),
        a new database will be created, else you just get the pointer to the file.

        If the database exists, we look into to get the state of the last call of the script, to manage the restart option, else we create a new database.

        Args:
            db (text): Name of the file used for storing sqlite3 database
            restart (boolean): (Optional) Indicates if your restart the process from the beginning or not
        
        Returns:
            cnx (sqlite3.Connection): Connection object (bound to the file _filename_)

    """

    cnx = sqlite3.connect(db)

    #
    # ---> Did we ask for a restart or not?
    #

    if not restart:

        # We didn't, so we continue the process. Does the table 'params' exist?

        res = cnx.execute("SELECT count(*) FROM sqlite_master WHERE type ='table' AND name ='params';").fetchone()

        if (res[0] == 1):

            # Yes, so we look for the status. If the status is empty, no step has been executed
            # so we have to recreate the database to start on clean basis.

            step = get_status(cnx)

            if (step is None):

                # No step in the database => Let's recreate the DB
                cnx.close()       
                cnx = db_create(db)

            else:

                # The script is in progress
                pass

        else:

            # No, there's no existing database, so we create one

            cnx = db_create(db)

    else:

        #
        #  'restart' is passed in args. So we drop & recreate the database
        #

        cnx = db_create(db)

    return cnx


#
#    ====================================================================
#     Get state of last call in the params table
#    ====================================================================
#

def get_status(cnx):

    """

        Gets the status of the last process, if it has beend stored, to handle a restart if needed.

        Args:
            cnx (sqlite3.Connection): Connection object

        Returns:
            value (text): Name of the last current path

    """

    res = cnx.execute("SELECT value FROM params WHERE key='last_path'").fetchone()

    #
    # ---> Get last step
    #

    if (res is not None):
        if (res[0] == ''):
            res = None
        else:
            res = res[0]

    return res


#
#    ====================================================================
#     Set state of last (=current) step executed in the params table
#    ====================================================================
#

def checkpoint_db(cnx, last_step, last_file = None, commit = False):

    """

        Sets the status of the current process by storing the name of the last well-executed step.

        Args:
            cnx (sqlite3.Connection): Connection object
            last_step (text): Name of the last well-executed step

        Returns:
            nothing

    """

    cnx.execute("UPDATE params SET value=? WHERE key='last_path'", (last_step,))
    cnx.execute("UPDATE params SET value=? WHERE key='last_file'", (last_file,))

    if (commit):
        cnx.commit()

    return 

    
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

    #
    # ---> DB connection
    #

    cnx = db_connect(db, True)

    #
    # ---> Path to walk
    #

    basepath    = "test"
    target      = "copie"

    logging.info("Parsing recursively directory %s", basepath)

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
                    output_exif_date = exif_date if exif_date is not None else ""
                    logging.info("(1){:<10} (2){} (3){} (4){} (5){:<30} (6){}".format(output_extracted_date, file_creation_day, output_exif_date, folder_date, f_name[:30], exif_hash))

                    # Inserting infos in DB

                    # Copying
                    
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

    # Closing database
    # ---

    cnx.close()



# -------------------------------------------
#  main call
# -------------------------------------------

if __name__ == '__main__':
    main()