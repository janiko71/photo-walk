#
# ================================= 
# Log into a DB all imported files
# =================================
#
#

import mimetypes
import utils
import os
import io
import sys
import re
import hashlib
import binascii
import time
import sqlite3
import signal
import logging
import shutil
import configparser

from datetime import datetime
from dateutil import parser

import PIL.Image as PILimage
from PIL.ExifTags import TAGS, GPSTAGS
import exifread

from colorama import Fore, Back, Style 
from colorama import init

from res.my_file_info import MyFileInfo


# -------------------------------------------
#  Files extensions list
# -------------------------------------------
#
# Filename, extension, mime file_type, filepath, creation date, modify date, filename date, file hash?
# exif date, exif infos, exif hash, imported, excluded
#

PICT_EXT_LIST = {".jpg", ".jpeg", ".jfif", ".bmp", ".gif", ".png", ".tif", ".tiff", ".webp"}
RAW_PICT_EXT_LIST = {".arw", ".cr2", ".cr3", ".crw", ".dcr", ".dcs", ".dng", ".drf", ".gpr", \
                     ".k25", ".kdc", ".mrw", ".nef", ".nrw", ".orf", ".pef", ".ptx", ".raf", \
                     ".raw", ".rw2", ".sr2", ".srf", ".srw", ".x3f"}
VIDEO_EXT_LIST = {".mpg", ".mp2", ".mpeg", ".mpe", ".mpv", ".mov", ".ogv", ".mp4", ".m4p", ".m4v", ".avi", ".ts", ".webm", ".wm", ".wmv", ".avchd"}



# -------------------------------------------
#  Global configuration
# -------------------------------------------

# Create a ConfigParser object
config = configparser.ConfigParser()

# Read the configuration file
config.read('photo-walk.ini') 

# Some DB variables
db = config['db']['name']
global cnx, nb_db_updates
cnx = None
nb_db_updates = 0
COMMIT_INTERVAL = 100


# -------------------------------------------
#  Log configuration
# -------------------------------------------

log_level_mapping = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

log_level_text = config['log']['level']
log_level = log_level_mapping.get(log_level_text, logging.INFO) # Default: INFO

# Configuration du format du log
log_format = "%(asctime)s - %(levelname)s: %(message)s"
log_date_format = "%Y%m%d_%H%M%S"
log_filename = f"log_{datetime.now().strftime(log_date_format)}.txt"

# --- logging variables

log_filepath    = "./log/"
os.makedirs(log_filepath, exist_ok=True)

logger          = logging.getLogger("photo-walk")
hdlr            = logging.FileHandler(log_filepath+log_filename)
formatter       = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
hdlr.setFormatter(formatter)

# --- Log handler

logger.addHandler(hdlr) 
logger.setLevel(log_level)



#
# ---> Some inits
#

global last_path
global last_file
last_path = None
last_file = None


def exit_handler(signum, frame):

    print()
    print("Normal exit from KeyboardInterrupt (CTRL+C)")
    #utils.checkpoint_db(cnx, last_path, last_file, commit = True)
    exit(0)



#
#    ====================================================================
#     Database connexion
#    ====================================================================
#
def db_connect(db):

    """

        Connects to the file which will be used for the sqlite3 database. If needed (= if you start a new search or if you've asked for a restart manually),
        a new database will be created, else you just get the pointer to the file.

        Args:
            db (text): Name of the file used for storing sqlite3 database
        
    """

    global cnx
    cnx = sqlite3.connect(db)

    #
    # ---> Existing DB or not?
    #

    try:

        res = cnx.execute("SELECT (1) FROM filelist").fetchone()

    except sqlite3.OperationalError as e:

        # No, there's no existing database, so we create one
        db_create(db)

    return 



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

    """

    global cnx
    #cnx = sqlite3.connect(db)
    logger.info("Creating tables on database %s", db)

    #
    # ---> Let's create the table used for storing files information
    #
    
    cnx.execute("CREATE TABLE filelist (\
                    fid INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, \
                    filename TINYTEXT, \
                    file_extension CHAR(30), \
                    mime_type CHAR(30), \
                    original_path VARCHAR(4096), \
                    dest_path VARCHAR(4096), \
                    file_path VARCHAR(4096) UNIQUE, \
                    creation_date TEXT, \
                    creation_date_short TEXT, \
                    modify_date TEXT, \
                    filename_date TEXT, \
                    folder_date TEXT, \
                    file_hash CHAR(256), \
                    exif_date TEXT, \
                    exif_content TEXT, \
                    exif_hash CHAR(256), \
                    size BIGINT, \
                    trt_date TEXT, \
                    walk_type CHAR(10)) \
                ")
    logger.info("Filetable successfully created")

    # ---> Some useful indexes to speed up the processing

    cnx.execute("CREATE INDEX index_original_path ON filelist (original_path, filename)")
    cnx.execute("CREATE INDEX index_exif_hash ON filelist (exif_hash)")
    cnx.execute("CREATE INDEX index_file_hash ON filelist (file_hash)")
    cnx.execute("CREATE INDEX index_file_path ON filelist (file_path)")
    logger.info("Indexes successfully created")

    cnx.commit()

    return 


#
#    ====================================================================
#     Commits DB if needed
#    ====================================================================
#
def walk_commit():

    global cnx, nb_db_updates

    nb_db_updates = nb_db_updates + 1
    if (nb_db_updates % COMMIT_INTERVAL == 0):
        cnx.commit()
    return

#
#    ====================================================================
#     Inserting file informations into DB, if needed
#    ====================================================================
#
def insert_into_DB(file_info):

    global cnx, nb_db_updates

    # Check if filepath is existing
    res = cnx.execute("SELECT 1 FROM filelist WHERE file_path=?", (file_info.file_path,))
    existing_file = res.fetchone()

    if not existing_file:
        #cnx.execute("INSERT INTO filelist (filename, extension, mime_type, original_path, dest_path, creation_date, creation_date_short, modify_date,\
        #            filename_date, folder_date, file_hash, exif_date, exif_content, exif_hash, size, trt_date, type) VALUES \
        #            (?, ?")
        requete_insertion = f'''INSERT INTO filelist ({', '.join(vars(file_info).keys())}) VALUES ({', '.join(['?' for _ in vars(file_info)])})'''
        cnx.execute(requete_insertion, tuple(vars(file_info).values()))
        walk_commit()

    return


#
#    ====================================================================
#     Get file information
#    ====================================================================
#

def get_file_info(dir_path, file_name):

    """
        Gets information for the file 
    """

    file_info = MyFileInfo()

    file_info.file_path = os.path.join(dir_path, file_name)
    file_info.filename = file_name

    # Obtenir l'extension du fichier
    file_info.file_extension = os.path.splitext(file_name)[1]

    # Obtenir le type MIME
    file_info.mime_type, _ = mimetypes.guess_type(file_name)

    # PS dates
    raw_modification_date = datetime.fromtimestamp(os.path.getmtime(file_info.file_path))
    file_info.modify_date = raw_modification_date.strftime('%Y-%m-%d %H:%M:%S')
    raw_creation_date = datetime.fromtimestamp(os.path.getctime(file_info.file_path))
    file_info.creation_date = raw_creation_date.strftime('%Y-%m-%d %H:%M:%S')
    file_info.creation_date_short = raw_creation_date.strftime('%Y-%m-%d')
    file_info.filename_date = extract_date_from_filename(file_info.filename)

    if (file_info.file_extension.lower() in PICT_EXT_LIST):

        # This is a picture

        file_info.walk_type = "PIC"
                    
        with open(file_info.file_path, 'rb') as file:
            tags = exifread.process_file(file, details=False)

        if 'EXIF DateTimeOriginal' in tags:

            date_text = tags['EXIF DateTimeOriginal'].printable
            date_parts = date_text.split(' ')
            file_info.exif_date = date_parts[0].replace(':', '-') + ' ' + date_parts[1]
            file_info.folder_date = file_info.exif_date[:10].replace(':','-')
            #img_exif_str = str(img_exif_data).encode('utf-8')
            #exif_hash = hashlib.sha256(img_exif_str).hexdigest()

            exif_info = ""
            for tag, value in tags.items():
                exif_info += f"{tag}:{value}\n"
            logger.debug(exif_info)
            # Get EXIF hash
            sha256_hasher = hashlib.sha256()
            sha256_hasher.update(exif_info.encode('utf-8'))
            file_info.exif_hash = sha256_hasher.hexdigest()

        else:

            file_info.exif_date = ""
            file_info.exif_hash = ""
            file_info.folder_date = file_info.creation_date_short

    elif (file_info.file_extension.lower() in RAW_PICT_EXT_LIST):

        # This is a RAW pic

        file_info.walk_type = "RAW"

        if file_info.extracted_date:
            file_info.folder_date = file_info.extracted_date
        else:
            file_info.folder_date = file_info.creation_date_short

    elif (file_info.file_extension.lower() in VIDEO_EXT_LIST):

        # This is a video

        file_info.walk_type = "VIDEO"

        if file_info.extracted_date:
            file_info.folder_date = file_info.extracted_date
        else:
            file_info.folder_date = file_info.creation_date_short

    # Hash computing for both images and videos
    # ---
            
    if ((file_info.file_extension.lower() in PICT_EXT_LIST) or (file_info.file_extension.lower() in RAW_PICT_EXT_LIST) or \
        (file_info.file_extension.lower() in VIDEO_EXT_LIST)):

        # File is PIC or RAW or VIDEO ==> added in DB

        # Open the file and read it in binary mode
        sha256_hasher = hashlib.sha256()
        with open(file_info.file_path, 'rb') as file:
            # Read the file in small chunks to efficiently handle large files
            for chunk in iter(lambda: file.read(4096), b''):
                sha256_hasher.update(chunk)

        # Get the hexadecimal representation of the hash
        file_info.file_hash = sha256_hasher.hexdigest()

    return file_info
    

#
#    ====================================================================
#     Extract date in the name of the file
#    ====================================================================
#

def extract_date_from_filename(filename):

    # Define a regex pattern to capture dates in various formats
    date_pattern = r'(\d{4}-\d{2}-\d{2})|(\d{2}-\d{2}-\d{4})|(\d{2}/\d{2}/\d{4})|(\d{8}-\d{6})|(\d{8}[T_]\d{6})'

    # Search for the date pattern in the filename
    match = re.search(date_pattern, filename)

    if match:
        # Extract the matched date from the captured groups
        extracted_date = match.group(0).replace('_','-') # To prevent parsing errors
        
        try:
            # Parse the extracted date using dateutil.parser
            parsed_date = parser.parse(extracted_date)
            
            # Reformat the parsed date to "yyyy-mm-dd" format
            reformatted_date = parsed_date.strftime('%Y-%m-%d')

        except Exception as e:

            reformatted_date = None            
        
        return reformatted_date
    else:
        return None



#
#    ====================================================================
#     Directory browsing (for target)
#    ====================================================================
#

def read_target(target):

    logger.info("Considering %s as target directory", target)

    nb_dest_files = 0
    nb_dest_pics = 0
    nb_dest_raw = 0
    nb_dest_videos = 0

    #
    # ---> Files discovering. Thanks to Python, we just need to call an existing function...
    #

    for dir_path, _, files in os.walk(target, topdown=True):

        for file_name in files:
                    
            file_info = get_file_info(dir_path, file_name)

            nb_dest_files = nb_dest_files + 1

            match file_info.walk_type:
                case "PIC":
                    nb_dest_pics = nb_dest_pics + 1
                case "RAW":
                    nb_dest_raw = nb_dest_raw + 1
                case "VIDEO":
                    nb_dest_videos = nb_dest_videos + 1

            if file_info.walk_type != "unknwon":

                insert_into_DB(file_info)


    return nb_dest_files, nb_dest_pics, nb_dest_raw, nb_dest_videos


#
#    ====================================================================
#     Directory browsing (for multiple source paths)
#    ====================================================================
#

def read_source(basepath_list):

    nb_source_files = 0
    nb_source_pics = 0
    nb_source_raw = 0
    nb_source_videos = 0

    # Loop over directories 

    for basepath in basepath_list:

        line        = basepath.rstrip("\n").split(";")
        
        if line[0] != '':

            basepath = line[0]
            logger.info("Considering %s as source directory", basepath)

            for dir_path, _, files in os.walk(basepath, topdown=True):

                for file_name in files:

                    file_info = get_file_info(dir_path, file_name)

                    nb_source_files = nb_source_files + 1

                    match file_info.walk_type:
                        case "PIC":
                            nb_source_pics = nb_source_pics + 1
                        case "RAW":
                            nb_source_raw = nb_source_raw + 1
                        case "VIDEO":
                            nb_source_videos = nb_source_videos + 1
        
    return nb_source_files, nb_source_pics, nb_source_raw, nb_source_videos


#
#    ====================================================================
#     Directory calculation (for all files in many directories)
#    ====================================================================
#

def target_lookup(target, cmd):

    """
        Args:
            basepath (text): Array of file paths we will look into.
            target: Target directory (where to copy files)
            cmd: Arguments line command -> read-target, read-source, testcopy, import

        Returns:
            t (time): The execution time of this function
            nb_to_process (int): The number of files we have to process   

    """

    # Read target to fill the DB with already imported files

    t0 = time.time()

    nb_dest_files, nb_dest_pics, nb_dest_raw, nb_dest_videos = read_target(target)

    t_dest_lookup = time.time() - t0

    return t_dest_lookup, nb_dest_files, nb_dest_pics, nb_dest_raw, nb_dest_videos



#
#    ====================================================================
#
#     Main part
#
#    ====================================================================
#

def main():

    # Colorama init

    init()

    # Checking arguments if any
    
    print("="*72)
    cmd = utils.check_arguments()
    logger.info("Command: {}".format(cmd))

    #
    # ---> Read the directory files list
    #

    basepath = config['directories']['sources'].split(',')

    logger.debug(basepath)
    logger.info("Default blocksize for this system is {} bytes.".format(io.DEFAULT_BUFFER_SIZE))

    target = config['directories']['destination']

    #
    # ---> DB connection
    #

    db_connect(db)

    #
    # ---> Catch the exit signal to commit the database with last checkpoint
    #

    signal.signal(signal.SIGINT, exit_handler)

    # 
    # ---> Infos to display
    #
                
    t_dest_lookup = 0.0
    t_source_lookup = 0.0
    t_copy = 0.0
    nb_dest_files = 0
    nb_dest_pics = 0
    nb_all_files = 0
    nb_all_pics = 0
    nb_all_raw = 0
    nb_all_videos = 0
    nb_files_copied = 0

    # Looking for files
    # ---

    if cmd == "read-target":
        t_dest_lookup, nb_dest_files, nb_dest_pics, nb_dest_raw, nb_dest_videos = target_lookup(target, cmd)
    print()
    print("-"*72)
    print("Files lookup duration: {:.2f} sec.".format(t_dest_lookup))
    print("-"*72)
    print("Nb. of destination files:", nb_dest_files)
    print("Nb. of destination PIC files:", nb_dest_pics)
    print("Nb. of destination RAW files:", nb_dest_raw)
    print("Nb. of destination Video files:", nb_dest_videos)
    print("="*72)
    print("Copy duration: {:.2f} sec.".format(t_copy))
    print("-"*72)
    print("Nb. of files:", nb_all_files)
    print("Nb. of PIC files:", nb_all_pics)
    print("Nb. of RAW files:", nb_all_raw)
    print("Nb. of Video files:", nb_all_videos)
    print("="*72)
    print("Nb. of DB updates:", nb_db_updates)
    print("-"*72)
    print("Nb. of files copied:", nb_files_copied)
    print("-"*72)

    # Calculate size of all files
    # ---

    res = cnx.execute("select sum(size) FROM filelist")
    size = res.fetchone()[0]
    if size is None:
        size = 0

    print("Size of all files: {}".format(utils.humanbytes(size)))
    print("="*72)

    # Closing database
    # ---

    cnx.commit()
    cnx.close()

    logger.info("Normal termination")

    return


# -------------------------------------------
#  main call
# -------------------------------------------

if __name__ == '__main__':

    main()