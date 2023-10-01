import os
import platform
import sys
import pefile 
import argparse
import warnings
from tabulate import tabulate  
from bs4 import BeautifulSoup as BS
from bs4 import Comment
from fnmatch import fnmatch

# Forked to create a utility with broader purpose to identify Auto-elevate and UAC Invocation 
# READ https://www.greyhathacker.net/?p=796

__author__ = 'Paul Davies'
__email__ = 'dev@mr-davies.co.uk'
__originalauthor__ = 'Dejan Levaja - dejan[@]levaja.com'
__license__ = 'GPLv2'
__version__ = "1.2.0"

ver = platform.platform()
autotable = []
exectable = []

# XML Parsing for Manufist is preferable but requires lxml - so HTML parser is used but throws warnings which need to be suppressed
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

def list_all_files(root, pattern, recursive):
    allfiles = []
    for path, subdirs, files in os.walk(root):
        for name in files:
            if fnmatch(name, pattern):
                fpath = os.path.join(path, name)
                allfiles.append(fpath)
        if not recursive:
            return allfiles
            break

    return allfiles


def get_data(manifest, fname, ignore_ms):
    if manifest:
        soup = BS(manifest, "html.parser")
        elevator = soup.find('autoelevate')
        level = soup.find('requestedexecutionlevel')
        if list_auto == True:
            if elevator:
                el= elevator.string 
                if str(el) == 'true':
                    desc = soup.find('description')
                    if desc:
                        description = desc.string
                    else:
                        description = ''
                    comments = soup.findAll(text=lambda text: isinstance(text, Comment))
                    for comment in comments:
                        if "Copyright" in comment:
                            manufacturer = comment.strip()
                            if 'microsoft' in manufacturer.lower():
                                if not ignore_ms:
                                    text = "%s,%s,%s" % (fname, description, manufacturer)
                                    autotable.append(text.split(','))
                            else:
                                text = "%s,%s,%s" % (fname, description, manufacturer)
                                autotable.append(text.split(','))

        if list_execution == True:
            if level:
                rel= level.attrs['level']
                if level.find('uiaccess'):
                    ui= level.attrs['uiaccess']
                else:
                    ui='Undefined'
                if rel.lower() in execution_level.lower(): 
                    desc = soup.find('description')
                    if desc:
                        description = desc.string
                    else:
                        description = '** No Description Field Present **'
                    comments = soup.findAll(string=lambda string: isinstance(string, Comment))
                    for comment in comments:
                        if "Copyright" in comment:
                            manufacturer = comment.strip()
                            if 'microsoft' in manufacturer.lower():
                                if not ignore_ms:
                                    if show_uiaccess:
                                        text = "%s,%s,%s,%s,%s" % (fname, rel, ui, description, manufacturer)
                                        exectable.append(text.split(','))
                                    else:
                                        text = "%s,%s,%s,%s" % (fname, rel, description, manufacturer)
                                        exectable.append(text.split(','))
                            else:
                                if show_uiaccess:
                                    text = "%s,%s,%s,%s,%s" % (fname, rel, ui, description, manufacturer)
                                    exectable.append(text.split(','))
                                else:
                                    text = "%s,%s,%s,%s" % (fname, rel, description, manufacturer)
                                    exectable.append(text.split(','))


def get_manifest(fname):
    pe = pefile.PE(fname)
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
            if name and hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            manifest = pe.get_data(
                                resource_lang.data.struct.OffsetToData,
                                resource_lang.data.struct.Size)
                            if 'MANIFEST' in name:
                                return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directory', help='Target directory.', default="C:\\Windows\\System32")
    parser.add_argument('-r', '--recursive', help='Scan Sub-folders as well.', action='store_false')
    parser.add_argument('-i', '--ignore-ms', help='Ignore files manufactured by Microsoft.', action='store_true')
    parser.add_argument('-la', '--list-auto', help='List the Auto Elevate Applications', action='store_false')
    parser.add_argument('-le', '--list-execution', help='List the Requested Execution Level', action='store_false')
    parser.add_argument('-el', '--execution-level', help='Specify the Execution Level to filter for (Default: asInvoker,highestAvailable,requireAdministrator)', default='asInvoker,highestAvailable,requireAdministrator')
    parser.add_argument('-su', '--show-uiaccess', help='Show uiaccess value, when outputting Requested Execution Level', action='store_true')
    args = vars(parser.parse_args())

    directory = args['directory']
    recursive = args['recursive']
    ignore_ms = args['ignore_ms']
    list_auto = args['list_auto']
    list_execution = args['list_execution']
    execution_level = args['execution_level']
    show_uiaccess = args['show_uiaccess']
    
    print('\nPlease wait, it can take some time...')
    filenames = list_all_files(directory, "*.exe", recursive)
    total = len(filenames)

    # progress
    for i, filename in enumerate(filenames):
        print('[%s of %s] Processing file "%s"' % (i+1, total, filename))
        manifest = get_manifest(filename)
        get_data(manifest, filename, ignore_ms)

    # print table
    if len(autotable) != 0:
        print ('\n\n[!] Total AutoElevate Applications found: %d' % len(autotable))
        headers = ['File', 'Description', 'Manufacturer']
        print (tabulate(autotable, headers, tablefmt='grid'))

    if len(exectable) != 0:
        print ('\n\n[!] Total Applications with Specified Elevation Level found: %d' % len(exectable))
        if show_uiaccess:
            headers = ['File', 'Execution Level', 'UIAccess', 'Description', 'Manufacturer']
        else:
            headers = ['File', 'Execution Level', 'Description', 'Manufacturer']
        print (tabulate(exectable, headers, tablefmt='grid'))

    sys.exit('\n\n[!] Done.\n\n')
