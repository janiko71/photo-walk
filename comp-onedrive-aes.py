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
#  Global configuration
# -------------------------------------------

# Some DB variables
db = "onedrive-aes.db"
global cnx, nb_db_updates, nb_db_records
cnx = None
nb_db_updates = 0
nb_db_records = 0
COMMIT_INTERVAL = 100


# -------------------------------------------
#  Log configuration
# -------------------------------------------

# Configuration du format du log
log_format = "%(asctime)s - %(levelname)s: %(message)s"
log_date_format = "%Y%m%d_%H%M%S"
log_filename = f"log_{datetime.now().strftime(log_date_format)}.txt"

# --- logging variables

log_filepath    = "./log-aes/"
os.makedirs(log_filepath, exist_ok=True)

logger          = logging.getLogger("onedrive-aes")
hdlr            = logging.FileHandler(log_filepath+log_filename, encoding='utf-8')
formatter       = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

hdlr.setFormatter(formatter)

# --- Log handler

logger.addHandler(hdlr) 
logger.setLevel(logging.INFO)


#
# ---> Some inits
#

global last_path
global last_file
last_path = None
last_file = None

global nb_files_copied, size_files_copied



#
#    ====================================================================
#     Exit when CTRL-C
#    ====================================================================
#
def exit_handler(signum, frame):

    global cnx

    cnx.commit()

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

    global cnx, nb_db_records
    cnx = sqlite3.connect(db)

    #
    # ---> Existing DB or not?
    #

    try:

        res = cnx.execute("SELECT count(fid) FROM filelist").fetchone()
        nb_db_records = res[0] 

    except sqlite3.OperationalError as e:

        # No, there's no existing database, so we create one
        try:
            db_create(db)
        except Exception as e:
            logger.info(f"Erreur DB {e}")
            exit(0)

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
                    std_filepath VARCHAR(4096) UNIQUE, \
                    in_onedrive CHAR(1), \
                    in_aes CHAR(1)) \
                ")
    logger.info("Filetable successfully created")

    # ---> Some useful indexes to speed up the processing

    cnx.execute("CREATE INDEX index_std_filepath ON filelist (std_filepath)")
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

    if (nb_db_updates % COMMIT_INTERVAL == 0):
        cnx.commit()
    return



#
#    ====================================================================
#     Directory browsing (AES)
#    ====================================================================
#

def read_aes():

    logger.info("Lecture AES")
    global nb_db_updates
    nb_db_updates = 0

    for dir_path, _, files in os.walk("P:\\", topdown=True):

        for file_name in files:

            # Check if filepath is existing in DB. If yes, we skip it. 
            std_filepath = os.path.join(dir_path.replace("P:\\", ""), file_name)
            res = cnx.execute("SELECT 1  FROM filelist WHERE std_filepath=?", (std_filepath,))
            existing_file = res.fetchone()
                        
            if not existing_file:

                requete_insertion = f'''INSERT INTO filelist (filename, std_filepath, in_aes) values('{file_name}', '{std_filepath}', "1")'''
                try:
                    cnx.execute(requete_insertion)
                    nb_db_updates = nb_db_updates + 1
                    walk_commit()
                except sqlite3.IntegrityError as ie:
                    logger.warning(f"Already existing file hash for {nb_db_updates} (ie)")

            else:

                requete_update = f'''UPDATE filelist SET in_aes = "1" where std_filepath = "{std_filepath}"'''
                cnx.execute(requete_update)
                nb_db_updates = nb_db_updates + 1
                walk_commit()                
    
    cnx.commit()

    return 



#
#    ====================================================================
#     Directory browsing (OneDrive)
#    ====================================================================
#

def read_onedrive():

    logger.info("Lecture OneDrive")
    global nb_db_updates
    nb_db_updates = 0

    #
    # ---> Files discovering. Thanks to Python, we just need to call an existing function...
    #

    for dir_path, _, files in os.walk("D:\OneDrive\Docs_Privés", topdown=True):

        for file_name in files:

            extension = os.path.splitext(file_name)[1].lower()
            if extension == '.aesd':
                real_filename = file_name[:-5]
            else:
                real_filename = file_name

            # Check if filepath is existing in DB. If yes, we skip it. 
            std_filepath = os.path.join(dir_path.replace("D:\\OneDrive\\Docs_Privés", ""), real_filename)
            res = cnx.execute("SELECT 1  FROM filelist WHERE std_filepath=?", (std_filepath,))
            existing_file = res.fetchone()
                        
            if not existing_file:

                requete_insertion = f'''INSERT INTO filelist (filename, std_filepath, in_onedrive) values('{file_name}', '{std_filepath}', "1")'''
                try:
                    cnx.execute(requete_insertion)
                    nb_db_updates = nb_db_updates + 1
                    walk_commit()
                except sqlite3.IntegrityError as ie:
                    logger.warning(f"Already existing file hash for {nb_db_updates} (ie)")


    return 




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

    global nb_files_copied, size_files_copied
                

    #
    # ---> Read OneDrive directory
    #

    read_aes()
    read_onedrive()


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