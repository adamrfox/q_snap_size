# q_snap_size
A project to report on the sizes of snapshots on a Qumulo cluster.

Customers like Qumulo for the analytics they provide about the data stored.  But one gap in the current UI is getting a granular view of the space consumed by an individual snapshot.  Fortunately, the API endpoints exist to get this information and that's what this project used to help customers see which snapshots are consuming space and how much.

The script simply requites Pyhon 3.x and the only module that may need to be added is 'keyring'.  This can be done in the standard way via pip.  It generates a file in csv format so that it can be imported into a spreadsheet which can then be used to generate reports in many formats.

The script is run as follows:
<pre>
Usage: q_snap_size.py [-hDvr] [-c user[:password]] [-t token] [-f token_file] [-s size] [-u unit] qumulo [path] ... [path]
-h | --help : Prints Usage
-D | --DEBUG : Generated info for debugging
-v | --verbose : Provides more details in the report
-r | --exclude-replication : Exclude replication-based snapshots
-c | --creds : Specify credentials format is user[:password]
-t | --token : Specify an access token
-f | --token-file : Specify is token file [def: .qfds_cred]
-s | --size : Exclude snapshots under a given size
-u | --unit : Specify a unit of size in the report [def: bytes]
qumulo : Name or IP of a Qumulo node
path ... path : One or more path patterns to include (regex supported), space separated
</pre>

## Authentication

Qumulo API calls must be authenticated and the script provides multuiple ways to do so:

1. Specify the credentials on the command line with the -c flag.  The format is user[:password].  If the password is not specified the script will check the keyring, and if still not found will prompt the user.
2. Specify an access token.  It is possible to generate an access token on the Qumulo cluster and specify it on the command line with the -t flag.
3. Specify an access token file.  The -f flag will read a specified file that will read the access token from that file.  By default it looks for .qfsd_cred as that is the default location for many qumulo CLI commands.
4. Keyring.  If a user and password are manually entered, the option will be given to put those credentials into the keyring of that system.  Once that is done, only the user needs to be specified either via the -c flag or manually via a user prompt.
5. If all else fails, the script will simply pronpt the user for credentials.  It will then offer to store the in the keyring for future use.

## Units

By default, all space units are specified in bytes.  Units can be used with the -s flag and in the report itself with the -u flag.  In both cases the default unit can be over-ridden with the standard abbreviations [kb, mb, gb, tb, pb].  They are case insenstive and the final 'b' is optional. 

## Minimum Privilege

The script can be run using the admin user, of course.  But for those who wish to run it as a user with minimal priveleges, the following are all that is needed:

<pre>
SNAPSHOT_READ
</pre>
