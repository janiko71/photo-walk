# 
# ---------------------------------------------------------------------------------------------------------------------------
# (1) Fill table with destination folder informations, without copying. Put the DB in destination folder root. Mark as protected.
# ---------------------------------------------------------------------------------------------------------------------------
# (2) Walk through source directory and copy if needed the files to the destination
# ---------------------------------------------------------------------------------------------------------------------------
#
# Reset = Clear DB + read the files
# Copy = Copying files without marking them as imported
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

#
#  Some constants
#

FMT_STR_CONSIDERING_DIR = "Considering " + Fore.LIGHTGREEN_EX + Style.DIM + "{}" + Fore.RESET + Style.RESET_ALL + "..."
FMT_STR_COMPLETED_DIR = "Completed directory lookup for " + Fore.LIGHTGREEN_EX + Style.DIM + "{}" + Fore.RESET + Style.RESET_ALL 


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

# --- logging variables

log_filepath    = "./log/"
os.makedirs(log_filepath, exist_ok=True)

logger          = logging.getLogger("photo-walk")
hdlr            = logging.FileHandler(log_filepath+config['log']['file'])
formatter       = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
hdlr.setFormatter(formatter)

# --- Log handler

logger.addHandler(hdlr) 
logger.setLevel(log_level)



#
# ---> Some inits
#

db      = config['db']['name']

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

            if (step == None):

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
    logger.info("Creating tables on database %s", db)

    #
    # ---> Dropping old tables
    #

    try:

        # Drop all tables

        cnx.execute("DROP TABLE filelist")
        cnx.execute("DROP TABLE params")
        print("Old tables deleted.")

    except sqlite3.OperationalError:

        # Exception means no old database

        print("No old database.")

    #
    # ---> Let's create the table used for storing files information
    #
    
    cnx.execute("CREATE TABLE filelist (\
                    fid INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, \
                    filename TINYTEXT, \
                    extension CHAR(30), \
                    mime_type CHAR(30), \
                    original_path VARCHAR(4096), \
                    dest_path VARCHAR(4096), \
                    creation_date TEXT, \
                    modify_date TEXT, \
                    filename_date TEXT, \
                    file_hash CHAR(256), \
                    exif_date TEXT, \
                    exif_content TEXT, \
                    exif_hash CHAR(256), \
                    size BIGINT, \
                    protected BOOL, \
                    imported BOOL, \
                    to_delete BOOL) \
                ")
    logger.info("Filetable successfully created")

    # ---> Some useful indexes to speed up the processing

    cnx.execute("CREATE INDEX index_original_path ON filelist (original_path, filename)")
    cnx.execute("CREATE INDEX index_exif_hash ON filelist (exif_hash)")
    cnx.execute("CREATE INDEX index_file_hash ON filelist (file_hash)")
    logger.info("Indexes successfully created")

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

    logger.info("Params table successfully created")

    cnx.commit()

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
            value (text): Name of the last executed process

    """

    res = cnx.execute("SELECT value FROM params WHERE key='last_step'").fetchone()

    #
    # ---> Get last step
    #

    if (res is not None):
        if (res[0] == ''):
            res= None
        else:
            res = res[0]

    #
    # ---> Get last ID (fid or hash)
    # 

    last_path = cnx.execute("SELECT value FROM params WHERE key='last_path'").fetchone()
    last_file = cnx.execute("SELECT value FROM params WHERE key='last_file'").fetchone()

    return last_path, last_file


#
#    ====================================================================
#     Set state of last (=current) step executed in the params table
#    ====================================================================
#

def checkpoint_db(cnx, last_path, last_file = None, commit = False):

    """

        Sets the status of the current process by storing the name of the last well-executed step.

        Args:  
            cnx (sqlite3.Connection): Connection object
            last_step (text): Name of the last well-executed step

        Returns:
            nothing

    """


    # We update the params table with the last well completed step

    cnx.execute("UPDATE params SET value=? WHERE key='last_path'", (last_path,))
    cnx.execute("UPDATE params SET value=? WHERE key='last_file'", (last_file,))

    if (commit):
        cnx.commit()

    return 


#
#    ====================================================================
#     Directory calculation (for all files in many directories)
#    ====================================================================
#

def directories_lookup(cnx, basepath_list, target, cmd):

    """
        Args:
            cnx (sqlite3.Connection): Connection object
            basepath (text): Array of file paths we will look into.
            target: Target directory (where to copy files)
            cmd: Arguments line command

        Returns:
            t (time): The execution time of this function
            nb_to_process (int): The number of files we have to process   

    """
                
    t_lookup = 0.0
    t_copy = 0.0
    nb_dest_files = 0
    nb_dest_pics = 0
    nb_dest_raw_videos = 0
    nb_all_files = 0
    nb_all_pics = 0
    nb_all_raw_videos = 0
    nb_files_copied = 0

    # First of all, we look into the dest folder to see what is present. No basepath, only target folder

    logger.info(FMT_STR_CONSIDERING_DIR.format(target) + " as a destination folder")
    t_lookup, nb_dest_files, nb_dest_pics, nb_dest_raw_videos, _ = directory_lookup(cnx, "", target, cmd)

    # Loop over directories to import

    for basepath in basepath_list:

        line        = basepath.rstrip("\n").split(";")

        if line[0] != '':

            basepath = line[0]

            logger.info(FMT_STR_CONSIDERING_DIR.format(basepath) + " as a source folder")
            t, nb_files, nb_pics, nb_raw_videos, nb_copy_directory = directory_lookup(cnx, basepath, target, cmd)
            
            t_copy += t
            nb_all_files += nb_files
            nb_all_pics += nb_pics
            nb_all_files += nb_raw_videos
            nb_files_copied += nb_copy_directory

    # Returning nb of files to process in the table. Should be the same as nb...

    r = cnx.execute("SELECT COUNT(*) FROM filelist")
    nb_to_process = r.fetchone()[0]

    return t_lookup, t_copy, nb_dest_files, nb_dest_pics, nb_dest_raw_videos, nb_all_files, nb_all_pics, nb_all_raw_videos, nb_files_copied


#
#    ====================================================================
#     Directory calculation (for all files in one directory)
#    ====================================================================
#

def directory_lookup(cnx, basepath, target, cmd):

    """

        Looks (hierarchically) for all files within the folder structure, and stores the path and the 
        name of each file. No file access is made (to save time).

        Args:
            cnx (sqlite3.Connection): Connection object
            basepath (text): Array of file paths we will look into.
            target: Target directory
            cmd: Command (arg line)

        Returns:
            t (time): The execution time of this function

    """

    global last_path, last_file

    # Start time
    chrono = utils.Chrono()
    chrono.start()

    # Nb of files init
    nb_files = 0
    nb_pics = 0
    nb_raw_videos = 0
    nb_files_copied = 0
    copy_files = False

    # Destination of source folder?

    if (basepath == ""):
        # Destination folder
        destination = True
        path_to_walk = target
    else:
        # Source folder(s)
        destination = False
        path_to_walk = basepath

    # Copy or not copy?

    if (cmd in ["copy", "import"]):
        copy_files = True


    #
    # ---> Files discovering. Thanks to Python, we just need to call an existing function...
    #

    for dir_path, _, files in os.walk(path_to_walk, topdown=True):

        #
        #  We just look for files, we don't process the directories
        #

        for file_name in files:

            # Hey, we got one (file)!

            file_path = os.path.join(dir_path, file_name)

            # Obtenir l'extension du fichier
            file_extension = os.path.splitext(file_name)[1]

            # Obtenir le type MIME
            file_mime_type, _ = mimetypes.guess_type(file_name)

            # PS dates
            modification_date = datetime.fromtimestamp(os.path.getmtime(file_path))
            formatted_modification_date = modification_date.strftime('%Y-%m-%d %H:%M:%S')
            creation_date = datetime.fromtimestamp(os.path.getctime(file_path))
            formatted_creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S')
            formatted_creation_date_short = creation_date.strftime('%Y-%m-%d')
            extracted_date = extract_date_from_filename(file_name)

            nb_files = nb_files + 1

            try:

                copy = False
                folder_date = None
                exif_date = None
                exif_hash = None
                
                if (file_extension.lower() in PICT_EXT_LIST):

                    # exif-like file

                    nb_pics = nb_pics + 1

                    copy = True
                    
                    """
                    img = PILimage.open(file_path)
                    img_exif_data = img._getexif()

                    if img_exif_data:

                        # Exif present

                        exif_date = img_exif_data.get(36867)
                        folder_date = exif_date[:10].replace(':','-')
                        img_exif_str = str(img_exif_data).encode('utf-8')
                        exif_hash = hashlib.sha256(img_exif_str).hexdigest()

                    else:

                        # No EXIF data
                        pass
                    """

                    with open(file_path, 'rb') as file:
                        tags = exifread.process_file(file, details=False)

                    if 'EXIF DateTimeOriginal' in tags:

                        date_text = tags['EXIF DateTimeOriginal'].printable
                        date_parts = date_text.split(' ')
                        exif_date = date_parts[0].replace(':', '-') + ' ' + date_parts[1]
                        folder_date = exif_date[:10].replace(':','-')
                        #img_exif_str = str(img_exif_data).encode('utf-8')
                        #exif_hash = hashlib.sha256(img_exif_str).hexdigest()

                        exif_info = ""
                        for tag, value in tags.items():
                            exif_info += f"{tag}:{value}\n"
                        logger.debug(exif_info)
                        # Get EXIF hash
                        sha256_hasher = hashlib.sha256()
                        sha256_hasher.update(exif_info.encode('utf-8'))
                        exif_hash = sha256_hasher.hexdigest()

                    else:

                        exif_date = ""
                        exif_hash = ""
                        folder_date = formatted_creation_date_short


                elif ((file_extension.lower() in RAW_PICT_EXT_LIST) or (file_extension.lower() in VIDEO_EXT_LIST)):
                    
                    # video or raw file

                    nb_raw_videos = nb_raw_videos + 1

                    copy = True
                    if extracted_date:
                        folder_date = formatted_creation_date_short
                    else:
                        folder_date = formatted_creation_date_short

                if ((file_extension.lower() in PICT_EXT_LIST) or (file_extension.lower() in RAW_PICT_EXT_LIST) or (file_extension.lower() in VIDEO_EXT_LIST)):

                    # File is PIC or RAW or VIDEO ==> added in DB

                    # Open the file and read it in binary mode
                    sha256_hasher = hashlib.sha256()
                    with open(file_path, 'rb') as file:
                        # Read the file in small chunks to efficiently handle large files
                        for chunk in iter(lambda: file.read(4096), b''):
                            sha256_hasher.update(chunk)

                    # Get the hexadecimal representation of the hash
                    file_hash = sha256_hasher.hexdigest()

                    res = cnx.execute("SELECT fid FROM filelist WHERE file_hash=?", (file_hash,)).fetchone()

                    if res is None:

                        # Only if not existing!

                        if destination:

                            cnx.execute("INSERT INTO filelist(filename, extension, mime_type, dest_path, size, creation_date, modify_date, filename_date, exif_date, exif_hash, file_hash, protected)\
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",\
                                    (file_name, file_extension, file_mime_type, dir_path, os.path.getsize(file_path), \
                                    formatted_creation_date, formatted_modification_date, extracted_date, exif_date, exif_hash, file_hash, True))

                        else:

                            cnx.execute("INSERT INTO filelist(filename, extension, mime_type, original_path, size, creation_date, modify_date, filename_date, exif_date, exif_hash, file_hash)\
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",\
                                    (file_name, file_extension, file_mime_type, dir_path, os.path.getsize(file_path), \
                                    formatted_creation_date, formatted_modification_date, extracted_date, exif_date, exif_hash, file_hash))


                            # Copying file only if not already imported

                    res = cnx.execute("SELECT fid, protected, imported FROM filelist WHERE file_hash=?", (file_hash,)).fetchone()

                    if res: 
                            
                            if (copy and copy_files and res[2] is None):

                                # Destination folder (based on date)
                                
                                yr = folder_date[0:4]
                                dest_dt = "{:04d}-{:02d}-{:02d}".format(int(yr), int(folder_date[5:7]), int(folder_date[8:10]))

                                yr_path = target + os.sep + yr
                                pic_path = yr_path + os.sep + dest_dt + os.sep
                            
                                output_extracted_date = extracted_date if extracted_date is not None else ""
                                output_exif_date = exif_date if exif_date is not None else ""
                                logger.info("(1){:<10} (2){} (3){} (4){} (5){:<30} (6){}".format(output_extracted_date, formatted_creation_date, output_exif_date, folder_date, file_name[:30], exif_hash))

                                # Copying
                                
                                if not(os.path.exists(yr_path)):
                                    str_log = f"Folder {yr_path} unkown, creating..."
                                    logger.info(str_log)
                                    os.makedirs(yr_path)
                                    
                                if not(os.path.exists(pic_path)):
                                    str_log = f"Folder {pic_path} unkown, creating..."
                                    logger.info(str_log)
                                    os.makedirs(pic_path)
                                
                                if not(os.path.exists(pic_path + file_name)):
                                    str_log = f"Copying {file_path} --> {pic_path + file_name}"
                                    nb_files_copied = nb_files_copied + 1
                                    logger.info(str_log)
                                    print("{} --> {}".format(file_path, pic_path + file_name))
                                    shutil.copy2(file_path, pic_path + file_name)

                                # If import => Mark as imported

                                if (cmd == 'import'):
                                    cnx.execute("UPDATE filelist SET imported = ? WHERE file_hash = (?)", (1, file_hash))
                
            except Exception as e:

                str_log = f"Error {str(e)} on {file_path}"
                logger.error(str_log)

            # Displaying progression and commit (occasionnaly)

            if ((nb_files % 100) == 0):
                last_path = file_path
                last_file = file_name
                print("Discovering #{} files ({:.2f} sec)".format(nb_files, chrono.elapsed()), end="\r", flush=True)
                cnx.commit()

            """
            except PermissionError:

                cnx.execute("INSERT INTO filelist(pre_hash, path, name, access_denied)\
                                VALUES (?, ?, ?, ?)",("?", root, name, True))

            except OSError as ose:

                cnx.execute("INSERT INTO filelist(pre_hash, path, name, os_errno, os_strerror)\
                                VALUES (?, ?, ?, ?, ?)",("?", root, name, ose.errno, ose.strerror))
            """

    #
    # ---> Last commit
    #

    checkpoint_db(cnx, "last_path_example", "last_file_example", commit = True)

    # End time
    chrono.stop()

    return chrono.elapsed(), nb_files, nb_pics, nb_raw_videos, nb_files_copied


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

    cnx = db_connect(db, cmd == 'reset')

    #
    # ---> Catch the exit signal to commit the database with last checkpoint
    #

    signal.signal(signal.SIGINT, exit_handler)

    # Looking for files
    # ---

    t_lookup, t_copy, nb_dest_files, nb_dest_pics, nb_dest_raw_videos, nb_all_files, nb_all_pics, nb_all_raw_videos, nb_files_copied = directories_lookup(cnx, basepath, target, cmd)
    print("Files lookup duration: {:.2f} sec.".format(t_lookup))
    print("-"*72)
    print("Nb. of destination files:", nb_dest_files)
    print("Nb. of destination PIC files:", nb_dest_pics)
    print("Nb. of destination RAW/Video files:", nb_dest_raw_videos)
    print("="*72)
    print("Copy duration: {:.2f} sec.".format(t_copy))
    print("-"*72)
    print("Nb. of files:", nb_all_files)
    print("Nb. of PIC files:", nb_all_pics)
    print("Nb. of RAW/Video files:", nb_all_raw_videos)
    print("="*72)
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

    cnx.close()

    return


# -------------------------------------------
#  main call
# -------------------------------------------

if __name__ == '__main__':

    main()