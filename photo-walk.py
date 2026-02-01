#
# ===========================================================================================
#  photo-walk.py
# ===========================================================================================
#  Version: 2026-02-01
#  Updated: 2026-02-01
#
#  Purpose:
#   - Build and maintain a historical DB of imported photos/videos
#   - Prevent duplicates by hashing every file, regardless of name or location
#
#  Main commands:
#   - rebuild : scan reference folder(s) and add everything to the DB
#   - read    : scan import sources and report what would be copied
#   - test    : copy to test folder, no DB updates
#   - import  : copy to reference folder and add to DB
#
#  Key ideas:
#   - The DB is the source of truth (not the current reference folder content)
#   - Hashing (SHA-256) is required for robust duplicate detection
#   - Performance can be tuned with [performance] in config.ini
#
# ===========================================================================================

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
import ffmpeg
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


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
config.read('config.ini', encoding='utf-8') 

# Some DB variables
db = config['db']['name']
COMMIT_INTERVAL = 100
DEFAULT_HASH_CHUNK_SIZE = 1024 * 1024
DEFAULT_MAX_WORKERS = max(1, (os.cpu_count() or 4))


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
hdlr            = logging.FileHandler(log_filepath+log_filename, encoding='utf-8')
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

@dataclass
class AppContext:
    config: configparser.ConfigParser
    logger: logging.Logger
    cnx: sqlite3.Connection | None = None
    nb_db_updates: int = 0
    nb_db_records: int = 0
    nb_files_copied: int = 0
    size_files_copied: int = 0
    hash_chunk_size: int = DEFAULT_HASH_CHUNK_SIZE
    max_workers: int = DEFAULT_MAX_WORKERS


#    ====================================================================
#     Exit when CTRL-C
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Handle SIGINT to exit cleanly (future: commit/checkpoint support)
#    -------------------------------------------------------------------------------------------

def exit_handler(signum, frame):

    print()
    print("Normal exit from KeyboardInterrupt (CTRL+C)")
    #utils.checkpoint_db(cnx, last_path, last_file, commit = True)
    exit(0)



#    ====================================================================
#     Print and log
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Print to stdout and write the same line to the log file
#    -------------------------------------------------------------------------------------------
def print_and_log(ctx, str1, str2=None, str3=None):

    str_resultat = str1 + (str(str2) if str2 is not None else "") + (str(str3) if str3 is not None else "")

    print(str_resultat)
    ctx.logger.info(str_resultat)

    return


#
#    ====================================================================
#     Database connection
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Open the SQLite DB and create tables if missing
#    -------------------------------------------------------------------------------------------
def db_connect(ctx, db):

    """

        Connects to the file which will be used for the sqlite3 database. If needed (= if you start a new search or if you've asked for a restart manually),
        a new database will be created, else you just get the pointer to the file.

        Args:
            db (text): Name of the file used for storing sqlite3 database
        
    """

    ctx.cnx = sqlite3.connect(db)

    #
    # ---> Existing DB or not?
    #

    try:

        res = ctx.cnx.execute("SELECT count(fid) FROM filelist").fetchone()
        ctx.nb_db_records = res[0]

    except sqlite3.OperationalError as e:

        # No, there's no existing database, so we create one
        db_create(ctx, db)

    return 



#    ====================================================================
#     Database creation
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Create tables and indexes for the file list
#    -------------------------------------------------------------------------------------------
def db_create(ctx, db):

    """

        Creates the database tables (unconditionnally).

        Args:
            db (text): Name of the file used for storing sqlite3 database

    """

    #cnx = sqlite3.connect(db)
    ctx.logger.info("Creating tables on database %s", db)

    #
    # ---> Let's create the table used for storing files information
    #
    
    ctx.cnx.execute("CREATE TABLE filelist (\
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
                    file_hash CHAR(256) UNIQUE, \
                    exif_date TEXT, \
                    exif_content TEXT, \
                    exif_hash CHAR(256), \
                    size BIGINT, \
                    trt_date TEXT, \
                    walk_type CHAR(10)) \
                ")
    ctx.logger.info("Filetable successfully created")

    # ---> Some useful indexes to speed up the processing

    ctx.cnx.execute("CREATE INDEX index_original_path ON filelist (original_path, filename)")
    ctx.cnx.execute("CREATE INDEX index_exif_hash ON filelist (exif_hash)")
    ctx.cnx.execute("CREATE INDEX index_file_hash ON filelist (file_hash)")
    ctx.cnx.execute("CREATE INDEX index_file_path ON filelist (file_path)")
    ctx.logger.info("Indexes successfully created")

    ctx.cnx.commit()

    return 


#    ====================================================================
#     Commit DB if needed
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Commit every COMMIT_INTERVAL inserts to reduce I/O
#    -------------------------------------------------------------------------------------------
def walk_commit(ctx):

    if (ctx.nb_db_updates % COMMIT_INTERVAL == 0):
        ctx.cnx.commit()
    return


#    ====================================================================
#     Insert file info into DB (if not already present)
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Insert one file record, guarding against duplicates
#    -------------------------------------------------------------------------------------------
def insert_into_DB(ctx, file_info):

    columns = [
        "filename",
        "file_extension",
        "mime_type",
        "original_path",
        "dest_path",
        "file_path",
        "creation_date",
        "creation_date_short",
        "modify_date",
        "filename_date",
        "folder_date",
        "file_hash",
        "exif_date",
        "exif_content",
        "exif_hash",
        "size",
        "trt_date",
        "walk_type",
    ]

    # Check (again) if filepath is existing. If we're here, it shouldn't exist
    res = ctx.cnx.execute("SELECT 1 FROM filelist WHERE file_path=?", (file_info.file_path,))
    existing_file = res.fetchone()

    if not existing_file:
        #cnx.execute("INSERT INTO filelist (filename, extension, mime_type, original_path, dest_path, creation_date, creation_date_short, modify_date,\
        #            filename_date, folder_date, file_hash, exif_date, exif_content, exif_hash, size, trt_date, type) VALUES \
        #            (?, ?")
        requete_insertion = f'''INSERT INTO filelist ({', '.join(columns)}) VALUES ({', '.join(['?' for _ in columns])})'''
        try:
            ctx.cnx.execute(requete_insertion, tuple(getattr(file_info, column) for column in columns))
            ctx.nb_db_updates = ctx.nb_db_updates + 1
            walk_commit(ctx)
        except sqlite3.IntegrityError as ie:
            ctx.logger.warning(f"Already existing file hash for {file_info.file_path} (ie)")

    return


#    ====================================================================
#     Get video file metadata (ffmpeg probe)
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Extract container and stream fields used for timestamps and size
#    -------------------------------------------------------------------------------------------
def get_video_metadata(file_path):

    try:
        probe = ffmpeg.probe(file_path)
        format_info = probe['format']
        video_metadata = {
            "duration": format_info.get('duration'),
            "size": format_info.get('size'),
            "bit_rate": format_info.get('bit_rate'),
            "creation_time": None,
        }
        for stream in probe['streams']:
            if stream['codec_type'] == 'video':
                video_metadata['width'] = stream.get('width')
                video_metadata['height'] = stream.get('height')
                if 'tags' in stream and 'creation_time' in stream['tags']:
                    video_metadata['creation_time'] = stream['tags']['creation_time']
                break
        return video_metadata
    except Exception as e:
        print(f"Error reading video metadata: {e}")
        return None

    

#    ====================================================================
#     Extract all file infos (metadata + hash)
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Build a MyFileInfo with dates, EXIF/video metadata, and SHA-256 hash
#    -------------------------------------------------------------------------------------------
def get_file_info(ctx, dir_path, file_name):

    """
        Gets information for the file 
    """

    file_info = MyFileInfo()

    file_info.file_path = os.path.join(dir_path, file_name)
    file_info.filename = file_name
    print(f"Looking {file_info.file_path}" + " "*80, end='\r', flush=True)

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
    file_info.trt_date = datetime.now().strftime("%Y%m%d%H%M%S")
    file_info.size = os.path.getsize(file_info.file_path)
    file_info.walk_type = "unknown"
    extracted_date = None

    if (file_info.file_extension.lower() in PICT_EXT_LIST):

        # This is a picture

        file_info.walk_type = "PIC"
                    
        with open(file_info.file_path, 'rb') as file:
            try:
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
                    ctx.logger.debug(exif_info)
                    # Get EXIF hash
                    sha256_hasher = hashlib.sha256()
                    sha256_hasher.update(exif_info.encode('utf-8'))
                    file_info.exif_hash = sha256_hasher.hexdigest()

                else:

                    file_info.exif_date = ""
                    file_info.exif_hash = ""
                    file_info.folder_date = file_info.creation_date_short

            except Exception as e:
                
                ctx.logger.error(f"Unknown error while retireving EXIF infos for {file_info.file_path} ({e})")
                # We need a folder date, even if EXIT was not readable
                file_info.folder_date = file_info.creation_date_short
            
    elif (file_info.file_extension.lower() in RAW_PICT_EXT_LIST):

        # This is a RAW pic

        file_info.walk_type = "RAW"

        if extracted_date:
            file_info.folder_date = extracted_date
        else:
            file_info.folder_date = file_info.creation_date_short

    elif (file_info.file_extension.lower() in VIDEO_EXT_LIST):

        # This is a video

        file_info.walk_type = "VIDEO"

        video_metadata = get_video_metadata(file_info.file_path)

        if video_metadata:
            extracted_date = video_metadata['creation_time']

        if extracted_date:
            file_info.folder_date = extracted_date[0:10]
        else:
            # file_info.folder_date = file_info.creation_date_short
            file_info.folder_date = file_info.modify_date[0:10]

    # Hash computing for both images and videos
    # ---
            
    if ((file_info.file_extension.lower() in PICT_EXT_LIST) or (file_info.file_extension.lower() in RAW_PICT_EXT_LIST) or \
        (file_info.file_extension.lower() in VIDEO_EXT_LIST)):

        # File is PIC or RAW or VIDEO ==> added in DB

        # Open the file and read it in binary mode
        sha256_hasher = hashlib.sha256()
        with open(file_info.file_path, 'rb') as file:
            # Read the file in small chunks to efficiently handle large files
            for chunk in iter(lambda: file.read(ctx.hash_chunk_size), b''):
                sha256_hasher.update(chunk)

        # Get the hexadecimal representation of the hash
        file_info.file_hash = sha256_hasher.hexdigest()

    return file_info
    

#
#    ====================================================================
#     Extract date in the name of the file
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Extract date from filename (best effort)
#    -------------------------------------------------------------------------------------------
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



#    ====================================================================
#     OS copy helper (single file)
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Copy one file and update counters/logs
#    -------------------------------------------------------------------------------------------
def os_file_copy(ctx, filepath, dest, cmd, size):

    # Check reference directory
    reference_file_path = os.path.join(dest, os.path.basename(filepath))

    # Verifying the need for copy
    existing_file = os.path.isfile(reference_file_path)

    if os.path.exists(reference_file_path):

        ctx.logger.info(f"File {reference_file_path} already exists.")

    else:

        try:
            # OS copy
            shutil.copy2(filepath, dest)
            ctx.nb_files_copied = ctx.nb_files_copied + 1
            ctx.size_files_copied = ctx.size_files_copied + size
            if cmd == "test":
                ctx.logger.info("%s copied in test mode (in %s)", filepath, dest)
            elif cmd == "import":
                ctx.logger.info("%s imported in %s", filepath, dest)
        except FileNotFoundError:
            ctx.logger.error("%s doesn't exist (import directory)", filepath)
        except PermissionError:
            ctx.logger.error(f"Wrong permissions for copying into {dest}")
        except Exception as e:
            ctx.logger.error(f"Unknown error while copying {filepath} ({e})")

    return 



#    ====================================================================
#     Copy file into YYYY/MM/DD folders
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Create date-based folders then copy the file
#    -------------------------------------------------------------------------------------------
def copy_file(ctx, file_path, dest, cmd, folder_date, size):
        
    # Create directory and subdirectories if not existing
    # ---

    if not os.path.exists(dest):
        os.makedirs(dest, exist_ok=True)

    year_dir = dest + os.path.sep + folder_date[0:4]
    if not os.path.exists(year_dir):
        os.makedirs(year_dir, exist_ok=True)

    month_dir = year_dir + os.path.sep + folder_date[5:7]
    if not os.path.exists(month_dir):
        os.makedirs(month_dir, exist_ok=True)

    final_dest_dir = month_dir + os.path.sep + folder_date
    if not os.path.exists(final_dest_dir):
        os.makedirs(final_dest_dir, exist_ok=True)

    os_file_copy(ctx, file_path, final_dest_dir, cmd, size)

    return 



#    ====================================================================
#     Scan reference directory (rebuild DB)
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Hash and record files from the reference directory into the DB
#    -------------------------------------------------------------------------------------------
def read_reference(ctx, reference):

    ctx.logger.info("Considering %s as reference directory", reference)

    nb_dest_files = 0
    nb_dest_pics = 0
    nb_dest_raw = 0
    nb_dest_videos = 0

    #
    # ---> Files discovering. Thanks to Python, we just need to call an existing function...
    #

    futures = []

    with ThreadPoolExecutor(max_workers=ctx.max_workers) as executor:
        for dir_path, _, files in os.walk(reference, topdown=True):

            for file_name in files:

                extension = os.path.splitext(file_name)[1].lower()

                if extension in PICT_EXT_LIST or extension in VIDEO_EXT_LIST or extension in RAW_PICT_EXT_LIST:

                    # Check if filepath is existing in DB. If yes, we skip it.
                    reference_file_path = os.path.join(dir_path, file_name)
                    res = ctx.cnx.execute("SELECT 1  FROM filelist WHERE file_path=?", (reference_file_path,))
                    existing_file = res.fetchone()

                    if not existing_file:
                        futures.append(executor.submit(get_file_info, ctx, dir_path, file_name))

                        if len(futures) >= ctx.max_workers * 2:
                            for finished in as_completed(futures[: ctx.max_workers]):
                                file_info = finished.result()
                                nb_dest_files = nb_dest_files + 1

                                match file_info.walk_type:
                                    case "PIC":
                                        nb_dest_pics = nb_dest_pics + 1
                                    case "RAW":
                                        nb_dest_raw = nb_dest_raw + 1
                                    case "VIDEO":
                                        nb_dest_videos = nb_dest_videos + 1

                                if file_info.walk_type != "unknown":
                                    insert_into_DB(ctx, file_info)
                            futures = futures[ctx.max_workers :]

        for finished in as_completed(futures):
            file_info = finished.result()
            nb_dest_files = nb_dest_files + 1

            match file_info.walk_type:
                case "PIC":
                    nb_dest_pics = nb_dest_pics + 1
                case "RAW":
                    nb_dest_raw = nb_dest_raw + 1
                case "VIDEO":
                    nb_dest_videos = nb_dest_videos + 1

            if file_info.walk_type != "unknown":
                insert_into_DB(ctx, file_info)


    return nb_dest_files, nb_dest_pics, nb_dest_raw, nb_dest_videos


#    ====================================================================
#     Scan import sources + compute what to do
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Hash files from import sources and decide copy/import actions
#    -------------------------------------------------------------------------------------------
def read_import_dir(ctx, basepath_list, cmd):

    nb_import_dir_files = 0
    nb_import_dir_pics = 0
    nb_import_dir_raw = 0
    nb_import_dir_videos = 0
    nb_pics_to_import= 0
    nb_raw_to_import = 0
    nb_videos_to_import = 0
    t_copy_files = 0.0

    futures = []

    # Loop over directories

    with ThreadPoolExecutor(max_workers=ctx.max_workers) as executor:
        for basepath in basepath_list:

            line        = basepath.rstrip("\n").split(";")
        
            if line[0] != '':

                basepath = line[0]
                ctx.logger.info("Considering %s as import directory", basepath)

                for dir_path, _, files in os.walk(basepath, topdown=True):

                    for file_name in files:
                        futures.append(executor.submit(get_file_info, ctx, dir_path, file_name))

                        if len(futures) >= ctx.max_workers * 2:
                            for finished in as_completed(futures[: ctx.max_workers]):
                                file_info = finished.result()

                                nb_import_dir_files = nb_import_dir_files + 1

                                match file_info.walk_type:
                                    case "PIC":
                                        nb_import_dir_pics = nb_import_dir_pics + 1
                                    case "RAW":
                                        nb_import_dir_raw = nb_import_dir_raw + 1
                                    case "VIDEO":
                                        nb_import_dir_videos = nb_import_dir_videos + 1

                                if file_info.walk_type in ['PIC', 'VIDEO', 'RAW']:

                                    # Check if the file is already in the DB
                                    cursor = ctx.cnx.cursor()
                                    cursor.execute("SELECT * FROM filelist WHERE file_hash=?", (file_info.file_hash, ))
                                    res = cursor.fetchone()

                                    if res:
                                        # existing
                                        ctx.logger.info("%s existing in DB", file_info.file_path)
                                    else:
                                        # Counting files to be copied/imported
                                        match file_info.walk_type:
                                            case "PIC":
                                                nb_pics_to_import = nb_pics_to_import + 1
                                            case "RAW":
                                                nb_raw_to_import = nb_raw_to_import + 1
                                            case "VIDEO":
                                                nb_videos_to_import = nb_videos_to_import + 1
                                        # doing what has to be done
                                        if cmd == "test":
                                            t0_copy = time.time()
                                            copy_file(ctx, file_info.file_path, ctx.config["directories"]["trash"], cmd, file_info.folder_date, file_info.size)
                                            t_copy_files = t_copy_files + (time.time() - t0_copy)
                                        elif cmd == "import":
                                            t0_copy = time.time()
                                            copy_file(ctx, file_info.file_path, ctx.config["directories"]["reference"], cmd, file_info.folder_date, file_info.size)
                                            t_copy_files = t_copy_files + (time.time() - t0_copy)
                                            file_info.original_path = os.path.dirname(file_info.file_path)
                                            insert_into_DB(ctx, file_info)
                                        elif cmd == "read":
                                            ctx.logger.info("%s would have been copied", file_info.file_path)

                            futures = futures[ctx.max_workers :]

        for finished in as_completed(futures):
            file_info = finished.result()

            nb_import_dir_files = nb_import_dir_files + 1

            match file_info.walk_type:
                case "PIC":
                    nb_import_dir_pics = nb_import_dir_pics + 1
                case "RAW":
                    nb_import_dir_raw = nb_import_dir_raw + 1
                case "VIDEO":
                    nb_import_dir_videos = nb_import_dir_videos + 1

            if file_info.walk_type in ['PIC', 'VIDEO', 'RAW']:

                # Check if the file is already in the DB
                cursor = ctx.cnx.cursor()
                cursor.execute("SELECT * FROM filelist WHERE file_hash=?", (file_info.file_hash, ))
                res = cursor.fetchone()

                if res:
                    # existing
                    ctx.logger.info("%s existing in DB", file_info.file_path)
                else:
                    # Counting files to be copied/imported
                    match file_info.walk_type:
                        case "PIC":
                            nb_pics_to_import = nb_pics_to_import + 1
                        case "RAW":
                            nb_raw_to_import = nb_raw_to_import + 1
                        case "VIDEO":
                            nb_videos_to_import = nb_videos_to_import + 1
                    # doing what has to be done
                    if cmd == "test":
                        t0_copy = time.time()
                        copy_file(ctx, file_info.file_path, ctx.config["directories"]["trash"], cmd, file_info.folder_date, file_info.size)
                        t_copy_files = t_copy_files + (time.time() - t0_copy)
                    elif cmd == "import":
                        t0_copy = time.time()
                        copy_file(ctx, file_info.file_path, ctx.config["directories"]["reference"], cmd, file_info.folder_date, file_info.size)
                        t_copy_files = t_copy_files + (time.time() - t0_copy)
                        file_info.original_path = os.path.dirname(file_info.file_path)
                        insert_into_DB(ctx, file_info)
                    elif cmd == "read":
                        ctx.logger.info("%s would have been copied", file_info.file_path)
        
    return nb_import_dir_files, nb_import_dir_pics, nb_import_dir_raw, nb_import_dir_videos, nb_pics_to_import, nb_raw_to_import, nb_videos_to_import, t_copy_files


#    ====================================================================
#     Import sources lookup wrapper
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Time the import scan and return counters
#    -------------------------------------------------------------------------------------------
def import_dir_lookup(ctx, basepath_list, cmd):

    """
        Args:
            basepath_list (text): Array of file paths we will look into.

        Returns:
            t (time): The execution time of this function
            nb_* (int): The number of files we have to process   

    """

    # Read reference to fill the DB with already imported files

    t0 = time.time()

    nb_import_dir_files, nb_import_dir_pics, nb_import_dir_raw, nb_import_dir_videos, nb_pics_to_import, nb_raw_to_import, nb_videos_to_import, t_copy_files = read_import_dir(ctx, basepath_list, cmd)

    t_import_dir_lookup = time.time() - t0

    return t_import_dir_lookup, nb_import_dir_files, nb_import_dir_pics, nb_import_dir_raw, nb_import_dir_videos, nb_pics_to_import, nb_raw_to_import, nb_videos_to_import, t_copy_files


#    ====================================================================
#     Reference lookup wrapper
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Time the reference scan and return counters
#    -------------------------------------------------------------------------------------------
def reference_lookup(ctx, reference):

    """
        Args:
            reference: Reference directory (where to copy files)

        Returns:
            t (time): The execution time of this function
            nb_* (int): The number of files we have to process   

    """

    # Read reference to fill the DB with already imported files

    t0 = time.time()

    nb_dest_files, nb_dest_pics, nb_dest_raw, nb_dest_videos = read_reference(ctx, reference)

    t_dest_lookup = time.time() - t0

    return t_dest_lookup, nb_dest_files, nb_dest_pics, nb_dest_raw, nb_dest_videos



#    ====================================================================
#     Main
#    ====================================================================
#
#    -------------------------------------------------------------------------------------------
#     Parse args, run selected command, and print summary
#    -------------------------------------------------------------------------------------------
def main():

    # Colorama init

    init()

    # Checking arguments if any
    
    cmd = utils.check_arguments()
    logger.info("Command: {}".format(cmd))

    #
    # ---> Read the directory files list
    #

    basepath = config['directories']['import_dirs'].split(',')

    logger.debug(basepath)
    logger.info("Default blocksize for this system is {} bytes.".format(io.DEFAULT_BUFFER_SIZE))

    reference = config['directories']['reference']

    #
    # ---> DB connection
    #

    ctx = AppContext(config=config, logger=logger)
    ctx.hash_chunk_size = config.getint("performance", "hash_chunk_size", fallback=DEFAULT_HASH_CHUNK_SIZE)
    ctx.max_workers = config.getint("performance", "max_workers", fallback=DEFAULT_MAX_WORKERS)
    db_connect(ctx, db)

    #
    # ---> Catch the exit signal to commit the database with last checkpoint
    #

    signal.signal(signal.SIGINT, exit_handler)

    # 
    # ---> Infos to display
    #

    t_dest_lookup = 0.0
    t_import_dir_lookup = 0.0
    t_copy_files = 0.0
    nb_dest_files = 0
    nb_dest_raw = 0
    nb_dest_videos = 0
    nb_dest_pics = 0
    nb_import_dir_files = 0
    nb_import_dir_pics = 0
    nb_import_dir_raw = 0
    nb_import_dir_videos = 0
    nb_pics_to_import = 0
    nb_raw_to_import = 0 
    nb_videos_to_import = 0
    ctx.nb_files_copied = 0
    ctx.size_files_copied = 0


    # Looking for files
    # ---

    match cmd:
        case "rebuild":
            t_dest_lookup, nb_dest_files, nb_dest_pics, nb_dest_raw, nb_dest_videos = reference_lookup(ctx, reference)
        case "read" | "test" | "import":
            t_import_dir_lookup, nb_import_dir_files, nb_import_dir_pics, nb_import_dir_raw, nb_import_dir_videos, nb_pics_to_import, nb_raw_to_import, nb_videos_to_import, t_copy_files = import_dir_lookup(ctx, basepath, cmd)

    # Calculate size of all files in DB
    # ---

    res = ctx.cnx.execute("select sum(size) FROM filelist")
    size = res.fetchone()[0]
    if size is None:
        size = 0

    print_and_log(ctx, "")
    print_and_log(ctx, "="*72)
    print_and_log(ctx, "Command: ", cmd)
    print_and_log(ctx, "DB records before run: ", ctx.nb_db_records)
    print_and_log(ctx, "Workers: ", ctx.max_workers)
    print_and_log(ctx, "Hash chunk size: {} bytes".format(ctx.hash_chunk_size))
    print_and_log(ctx, "="*72)
    print_and_log(ctx, "REFERENCE (scan)")
    print_and_log(ctx, "Reference scan duration: {:.2f} sec.".format(t_dest_lookup))
    print_and_log(ctx, "-"*72)
    print_and_log(ctx, "New files in reference not in DB: ", nb_dest_files)
    print_and_log(ctx, "New reference PIC files: ", nb_dest_pics)
    print_and_log(ctx, "New reference RAW files: ", nb_dest_raw)
    print_and_log(ctx, "New reference Video files: ", nb_dest_videos)
    print_and_log(ctx, "="*72)
    if cmd in ["import", "test"]:
        import_duration_label = "Import sources scan/copy duration: "
    else:
        import_duration_label = "Import sources scan duration: "
    print_and_log(ctx, "IMPORT SOURCES (scan)")
    print_and_log(ctx, "{}{:.2f} sec.".format(import_duration_label, t_import_dir_lookup))
    print_and_log(ctx, "-"*72)
    print_and_log(ctx, "Files found in import sources: ", nb_import_dir_files)
    print_and_log(ctx, "PIC files in import sources: ", nb_import_dir_pics)
    print_and_log(ctx, "RAW files in import sources: ", nb_import_dir_raw)
    print_and_log(ctx, "Video files in import sources: ", nb_import_dir_videos)
    print_and_log(ctx, "-"*72)
    print_and_log(ctx, "IMPORT PLAN")
    print_and_log(ctx, "Files to import (not present): ", nb_pics_to_import + nb_raw_to_import + nb_videos_to_import)
    print_and_log(ctx, "PIC files to import (not present): ", nb_pics_to_import)
    print_and_log(ctx, "RAW files to import (not present): ", nb_raw_to_import)
    print_and_log(ctx, "Video files to import (not present): ", nb_videos_to_import)
    print_and_log(ctx, "="*72)
    print_and_log(ctx, "DB updates during run: ", ctx.nb_db_updates)
    print_and_log(ctx, "-"*72)
    print_and_log(ctx, "Total size of all files in DB: {}".format(utils.humanbytes(size)))
    print_and_log(ctx, "="*72)
    print_and_log(ctx, "COPY RESULT")
    if cmd == "import":
        print_and_log(ctx, "Nb. of files copied: ", ctx.nb_files_copied)
    elif cmd == "test":
        print_and_log(ctx, "Nb. of files copied: ", ctx.nb_files_copied, " (test mode)")
    else:
        print_and_log(ctx, "Nb. of files copied: ", ctx.nb_files_copied, " (no copy)")
    print_and_log(ctx, "File copy duration: {:.2f} sec.".format(t_copy_files))
    print_and_log(ctx, "-"*72)
    print_and_log(ctx, "Size of files copied: {}".format(utils.humanbytes(ctx.size_files_copied)))
    print_and_log(ctx, "="*72)

    # Closing database
    # ---

    ctx.cnx.commit()
    ctx.cnx.close()

    logger.info("Normal termination")

    return


# -------------------------------------------
#  main call
# -------------------------------------------

if __name__ == '__main__':

    main()
