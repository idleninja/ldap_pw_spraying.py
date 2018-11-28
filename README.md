# This script is intended for both blue and red teams but the idea was born from blue.
The script requires a list of users, passwords, ldap server(s) to authenticate against, and a domain name. 
It then loops through each password and user trying one password for each user in the list before continuing to the next password.
It performs a LDAP simple bind authentication in a thread with a default queue size of 450 and prioritizes the quickest responding servers first.

With the 'stealthy' option enabled, once there are one or more enumerated credentials discovered, the script will attempt to authenticate
using the discovered credentials to a defined 75% or below fail-to-total ratio. The intent is to drive successful authentication event codes
into the SIEM and influence alert logic from a single source (i.e. multiple failed auths from single source alert).
