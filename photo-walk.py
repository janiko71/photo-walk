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

from datetime import datetime
from dateutil import parser

import PIL.Image as PILimage

from colorama import Fore, Back, Style 
from colorama import init

#
#  Some constants
#

FMT_STR_CONSIDERING_DIR = "Considering " + Fore.LIGHTGREEN_EX + Style.DIM + "{}" + Fore.RESET + Style.RESET_ALL + "..."
FMT_STR_COMPLETED_DIR = "Completed directory lookup for " + Fore.LIGHTGREEN_EX + Style.DIM + "{}" + Fore.RESET + Style.RESET_ALL 


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
# ---> Some inits
#

algo = "sha1"
db = utils.db_name
filelist = utils.filelist_name

restart = False
global last_path
global last_file
last_path = None
last_file = None


def exit_handler(signum, frame):

    print()
    print("Normal exit from KeyboardInterrupt (CTRL+C)")
    utils.checkpoint_db(cnx, last_path, last_file, commit = True)
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
    logging.info("Creating database %s", db)

    #
    # ---> Dropping old tables
    #

    try:

        # Drop all tables

        cnx.execute("DROP TABLE filelist")
        cnx.execute("DROP TABLE params")
        print("Old database deleted.")

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

    if (res != None):
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

def directories_lookup(cnx, basepath_list):

    """
        Args:
            cnx (sqlite3.Connection): Connection object
            basepath (text): Array of file paths we will look into.

        Returns:
            t (time): The execution time of this function
            nb_to_process (int): The number of files we have to process   

    """
                
    t_elaps = 0.0

    # We look for the directories already looked up

    completed_dir = []

    res = cnx.execute("SELECT ALL value FROM params WHERE key = 'completed_dir'")

    for dir_name in res:
        completed_dir.append(dir_name[0])
        print(FMT_STR_COMPLETED_DIR.format(dir_name[0]))

    # Loop over directories

    for basepath in basepath_list:

        line        = basepath.rstrip("\n").split(";")

        if line[0] != '':

            basepath = line[0]

            # If the directory has been completed, we skip it. Else, we restart the lookup from the beginning.

            if (basepath not in completed_dir):

                # Restart point here. We delete what has been done for this directory (for it has not been completed)
                cnx.execute("DELETE FROM filelist WHERE filepath=?", (basepath,))
                cnx.commit()

                logging.info(FMT_STR_CONSIDERING_DIR.format(basepath))
                t = directory_lookup(cnx, basepath)
                
                t_elaps += t

    # Returning nb of files to process in the table. Should be the same as nb...

    r = cnx.execute("SELECT COUNT(*) FROM filelist")
    nb_to_process = r.fetchone()[0]

    return t_elaps, nb_to_process


#
#    ====================================================================
#     Directory calculation (for all files in one directory)
#    ====================================================================
#

def directory_lookup(cnx, basepath):

    """

        Looks (hierarchically) for all files within the folder structure, and stores the path and the 
        name of each file. No file access is made (to save time).

        Args:
            cnx (sqlite3.Connection): Connection object
            basepath (text): Array of file paths we will look into.

        Returns:
            t (time): The execution time of this function

    """

    global last_path, last_file

    # Start time
    chrono = utils.Chrono()
    chrono.start()

    # Nb of files init
    nb = 0

    # Filepath init

    if (basepath == ""):
        basepath = "."

    #
    # ---> Files discovering. Thanks to Python, we just need to call an existing function...
    #

    for root, _, files in os.walk(basepath, topdown=True):

        #
        #  We just look for files, we don't process the directories
        #

        for name in files:

            # Hey, we got one (file)!

            nb = nb + 1
            cnx.execute("INSERT INTO filelist(filename, filepath, size)\
                            VALUES (?, ?, ?)",(name, root, 1))

            # Displaying progression and commit (occasionnaly)

            if ((nb % 100) == 0):
                last_path = ""
                lasy_file = name
                print("Discovering #{} files ({:.2f} sec)".format(nb, chrono.elapsed()), end="\r", flush=True)
                if ((nb % 1000) == 0):
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

    return chrono.elapsed()


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
        
        # Parse the extracted date using dateutil.parser
        parsed_date = parser.parse(extracted_date)
        
        # Reformat the parsed date to "yyyy-mm-dd" format
        reformatted_date = parsed_date.strftime('%Y-%m-%d')
        
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

    # 
    # ---> Check for 'restart' argument
    #

    arguments = utils.check_arguments(sys.argv)

    if ("restart" in arguments):
        restart = True
    else:
        restart = False

    #
    # ---> Catch the exit signal to commit the database with last checkpoint
    #

    signal.signal(signal.SIGINT, exit_handler)

    #
    # ---> Read the directory files list
    #

    with open(filelist, "r") as f:
        basepath = f.readlines()

    logging.debug(basepath)
    logging.info("Default blocksize for this system is {} bytes.".format(io.DEFAULT_BUFFER_SIZE))

    #
    # ---> DB connection
    #

    cnx = db_connect(db, restart)

    # Looking for files
    # ---

    t, nb = directories_lookup(cnx, basepath)
    print("Files lookup duration: {:.2f} sec for {} files.".format(t, nb))

    # Calculate size of all files
    # ---

    res = cnx.execute("select sum(size) FROM filelist")
    size = res.fetchone()[0]

    print("Size of all files: {}".format(utils.humanbytes(size)))

    # Closing database
    # ---

    cnx.close()

    return


# -------------------------------------------
#  main call
# -------------------------------------------

if __name__ == '__main__':

    main()