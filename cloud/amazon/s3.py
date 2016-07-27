#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: s3
short_description: manage objects in S3.
description:
    - This module allows the user to manage S3 buckets and the objects within them. Includes support for creating and deleting both objects and buckets, retrieving objects as files or strings and generating download links. This module has a dependency on python-boto.
version_added: "1.1"
options:
  aws_access_key:
    description:
      - AWS access key id. If not set then the value of the AWS_ACCESS_KEY environment variable is used.
    required: false
    default: null
    aliases: [ 'ec2_access_key', 'access_key' ]
  aws_secret_key:
    description:
      - AWS secret key. If not set then the value of the AWS_SECRET_KEY environment variable is used.
    required: false
    default: null
    aliases: ['ec2_secret_key', 'secret_key']
  bucket:
    description:
      - Bucket name.
    required: true
    default: null
    aliases: []
  dest:
    description:
      - The destination file path when downloading an object/key with a GET operation.
      - The destination folder path when downloading objects/keys with a GET recursive operation. Only with the recurse parameter "true"
    required: false
    aliases: []
    version_added: "1.3"
  encrypt:
    description:
      - When set for PUT mode, asks for server-side encryption
    required: false
    default: no
    version_added: "2.0"
  expiration:
    description:
      - Time limit (in seconds) for the URL generated and returned by S3/Walrus when performing a mode=put or mode=geturl operation.
    required: false
    default: 600
    aliases: []
  headers:
    description:
      - Custom headers for PUT operation, as a dictionary of 'key=value' and 'key=value,key=value'.
    required: false
    default: null
    version_added: "2.0"
  marker:
    description:
      - Specifies the key to start with when using list mode. Object keys are returned in alphabetical order, starting with key after the marker in order.
    required: false
    default: null
    version_added: "2.0"
  max_keys:
    description:
      - Max number of results to return in list mode, set this if you want to retrieve fewer than the default 1000 keys.
    required: false
    default: 1000
    version_added: "2.0"
  metadata:
    description:
      - Metadata for PUT operation, as a dictionary of 'key=value' and 'key=value,key=value'.
    required: false
    default: null
    version_added: "1.6"
  mode:
    description:
      - Switches the module behaviour between put (upload), get (download), geturl (return download url, Ansible 1.3+), getstr (download object as string (1.3+)), list (list keys, Ansible 2.0+), create (bucket), delete (bucket), and delobj (delete object, Ansible 2.0+).
    required: true
    choices: ['get', 'put', 'delete', 'create', 'geturl', 'getstr', 'delobj', 'list']
  object:
    description:
      - Keyname of the object inside the bucket. Can be used to create "virtual directories", see examples.
    required: false
    default: null
  permission:
    description:
      - This option lets the user set the canned permissions on the object/bucket that are created. The permissions that can be set are 'private', 'public-read', 'public-read-write', 'authenticated-read'. Multiple permissions can be specified as a list.
    required: false
    default: private
    version_added: "2.0"
  prefix:
    description:
      - Limits to keys that begin with the specified prefix for list, get, put and delobj mode
    required: false
    default: null
    version_added: "2.0"
  recurse:
    description:
      - Get, Put or Delete all keys that begin with the specified prefix for get, put or delobj mode
    required: false
    default: false
    version_added: "2.2"
  version:
    description:
      - Version ID of the object inside the bucket. Can be used to get a specific version of a file if versioning is enabled in the target bucket.
    required: false
    default: null
    aliases: []
    version_added: "2.0"
  overwrite:
    description:
      - Force overwrite either locally on the filesystem or remotely with the object/key. Used with PUT and GET operations. Boolean or one of [always, never, different], true is equal to 'always' and false is equal to 'never', new in 2.0
    required: false
    default: 'always'
    version_added: "1.2"
  region:
    description:
     - "AWS region to create the bucket in. If not set then the value of the AWS_REGION and EC2_REGION environment variables are checked, followed by the aws_region and ec2_region settings in the Boto config file.  If none of those are set the region defaults to the S3 Location: US Standard.  Prior to ansible 1.8 this parameter could be specified but had no effect."
    required: false
    default: null
    version_added: "1.8"
  retries:
    description:
     - On recoverable failure, how many times to retry before actually failing.
    required: false
    default: 0
    version_added: "2.0"
  s3_url:
    description:
      - S3 URL endpoint for usage with Eucalypus, fakes3, etc.  Otherwise assumes AWS
    default: null
    aliases: [ S3_URL ]
  src:
    description:
      - The source file path when performing a PUT operation.
      - The source folder path when performing a PUT recursive operation. Only with the recurse parameter "true"
    required: false
    default: null
    aliases: []
    version_added: "1.3"

requirements: [ "boto" ]
author:
    - "Lester Wade (@lwade)"
extends_documentation_fragment: aws
'''

EXAMPLES = '''
# Simple PUT operation
- s3: bucket=mybucket object=/my/desired/key.txt src=/usr/local/myfile.txt mode=put

# Simple GET operation
- s3: bucket=mybucket object=/my/desired/key.txt dest=/usr/local/myfile.txt mode=get

# Get a specific version of an object.
- s3: bucket=mybucket object=/my/desired/key.txt version=48c9ee5131af7a716edc22df9772aa6f dest=/usr/local/myfile.txt mode=get

# Get all object with prefix key
- s3: bucket=mybucket prefix=/my/desired dest=/usr/local recurse=true mode=get

# PUT/upload with metadata
- s3: bucket=mybucket object=/my/desired/key.txt src=/usr/local/myfile.txt mode=put metadata='Content-Encoding=gzip,Cache-Control=no-cache'

# PUT/upload with custom headers
- s3: bucket=mybucket object=/my/desired/key.txt src=/usr/local/myfile.txt mode=put headers=x-amz-grant-full-control=emailAddress=owner@example.com

# Put all object with prefix key
- s3: bucket=mybucket prefix=/my/desired src=/usr/local recurse=true mode=put

# List keys simple
- s3: bucket=mybucket mode=list

# List keys all options
- s3: bucket=mybucket mode=list prefix=/my/desired/ marker=/my/desired/0023.txt max_keys=472

# Create an empty bucket
- s3: bucket=mybucket mode=create permission=public-read

# Create a bucket with key as directory, in the EU region
- s3: bucket=mybucket object=/my/directory/path mode=create region=eu-west-1

# Delete a bucket and all contents
- s3: bucket=mybucket mode=delete

# GET an object but dont download if the file checksums match. New in 2.0
- s3: bucket=mybucket object=/my/desired/key.txt dest=/usr/local/myfile.txt mode=get overwrite=different

# Delete an object from a bucket
- s3: bucket=mybucket object=/my/desired/key.txt mode=delobj

# Delete all objects from a bucket with prefix
- s3: bucket=mybucket prefix=/my/desired recurse=true mode=delobj

'''

import os
import urlparse
from ssl import SSLError
import re
from datetime import date

try:
    import boto
    import boto.ec2
    from boto.s3.connection import Location
    from boto.s3.connection import OrdinaryCallingFormat
    from boto.s3.connection import S3Connection
    from boto.s3.acl import CannedACLStrings
    from boto.dynamodb2.results import ResultSet

    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False

DEFAULT_MAX_KEYS = 1000

def key_check(module, s3, bucket, obj, recurse, version=None, marker=None, max_keys=DEFAULT_MAX_KEYS):
    try:
        bucket = s3.lookup(bucket)

        if recurse:
            key_check = bucket.get_all_keys(prefix=obj, max_keys=max_keys, marker=marker)
        else:
            key_check = bucket.get_key(obj, version_id=version)
    except s3.provider.storage_response_error as e:
        if version is not None and e.status == 400: # If a specified version doesn't exist a 400 is returned.
            key_check = None
        else:
            module.fail_json(msg=str(e))
    if key_check:
        return True
    else:
        return False

def keysum(module, s3, bucket, obj, recurse, version=None, marker=None, max_keys=DEFAULT_MAX_KEYS):
    if recurse:
        bucket = s3.lookup(bucket)

        rskeys = bucket.get_all_keys(prefix=obj, marker=marker, max_keys=max_keys)
    else:
        rskeys = ResultSet()
        rskeys.to_call(get_resultset_onekey, s3, bucket, obj, version=version)

    dict_md5_remote = {}

    for key_check in rskeys:

        md5_remote = key_check.etag[1:-1]
        etag_multipart = '-' in md5_remote # Check for multipart, etag is not md5
        if etag_multipart is True:
            module.fail_json(msg="Files uploaded with multipart of s3 are not supported with checksum, unable to compute checksum.")

        dict_md5_remote.update({ key_check.name: md5_remote })

    if len(dict_md5_remote) > 0:
        return dict_md5_remote
    else:
        return None

def bucket_check(module, s3, bucket):
    try:
        result = s3.lookup(bucket)
    except s3.provider.storage_response_error as e:
        module.fail_json(msg= str(e))
    if result:
        return True
    else:
        return False

def create_bucket(module, s3, bucket, location=None):
    if location is None:
        location = Location.DEFAULT
    try:
        bucket = s3.create_bucket(bucket, location=location)
        for acl in module.params.get('permission'):
            bucket.set_acl(acl)
    except s3.provider.storage_response_error as e:
        module.fail_json(msg= str(e))
    if bucket:
        return True

def get_bucket(module, s3, bucket):
    try:
        return s3.lookup(bucket)
    except s3.provider.storage_response_error as e:
        module.fail_json(msg= str(e))

def list_keys(module, bucket_object, prefix, marker, max_keys):
    all_keys = bucket_object.get_all_keys(prefix=prefix, marker=marker, max_keys=max_keys)

    keys = [x.key for x in all_keys]

    module.exit_json(msg="LIST operation complete", s3_keys=keys)

def delete_bucket(module, s3, bucket):
    try:
        bucket = s3.lookup(bucket)
        bucket_contents = bucket.list()
        bucket.delete_keys([key.name for key in bucket_contents])
        bucket.delete()
        return True
    except s3.provider.storage_response_error as e:
        module.fail_json(msg= str(e))

def delete_key(module, s3, bucket, obj, recurse=False, marker=None, max_keys=DEFAULT_MAX_KEYS):
    try:
        bucket = s3.lookup(bucket)

        if recurse:
            keys_name = []
            keys = bucket.get_all_keys(prefix=obj, marker=marker, max_keys=max_keys)

            for key in keys: keys_name.append(key.name)

            if len(keys_name) > 0:
                bucket.delete_keys(keys_name)
                module.exit_json(msg="Objects deleted from bucket %s"%bucket, files=keys_name, changed=True)
            else:
                module.exit_json(msg="No objects found in bucket %s"%bucket, obj=obj, changed=True)
        else:
            bucket.delete_key(obj)
            module.exit_json(msg="Object deleted from bucket %s"%bucket, files=obj, changed=True)

    except s3.provider.storage_response_error as e:
        module.fail_json(msg= str(e))

def create_dirkey(module, s3, bucket, obj):
    try:
        bucket = s3.lookup(bucket)
        key = bucket.new_key(obj)
        key.set_contents_from_string('')
        module.exit_json(msg="Virtual directory %s created in bucket %s" % (obj, bucket.name), changed=True)
    except s3.provider.storage_response_error as e:
        module.fail_json(msg= str(e))

def path_check(path):
    if os.path.exists(path):
        return True
    else:
        return False


def upload_s3file(module, s3, bucket, obj, src, expiry, metadata, encrypt, headers, return_upload_files=None, next_upload_s3file=False):
    if return_upload_files is None:
        return_upload_files = []

    try:

        bucket = s3.lookup(bucket)
        key = bucket.new_key(obj)
        if metadata:
            for meta_key in metadata.keys():
                key.set_metadata(meta_key, metadata[meta_key])

        key.set_contents_from_filename(src, encrypt_key=encrypt, headers=headers)
        for acl in module.params.get('permission'):
            key.set_acl(acl)
        url = key.generate_url(expiry)
        return_upload_files.append({ 'obj': obj, 'upload': True, 'url': url, 'expiry': expiry, 'src': src })

        if not next_upload_s3file:
            module.exit_json(msg="PUT operation complete", files=return_upload_files, changed=True)
        else:
            return return_upload_files

    except s3.provider.storage_copy_error as e:
        module.fail_json(msg= str(e))

def download_s3file(module, s3, bucket, obj, recurse, dest, retries, version=None, marker=None, max_keys=DEFAULT_MAX_KEYS, return_download_files=None, next_download_s3file=False):
    if return_download_files is None:
        return_download_files = []

    if recurse:
        bucket = s3.lookup(bucket)
        rskeys = bucket.get_all_keys(prefix=obj, marker=marker, max_keys=max_keys)
    else:
        rskeys = ResultSet()
        rskeys.to_call(get_resultset_onekey, s3, bucket, obj, version=version)

    download_keys = False

    for key in rskeys:
      # retries is the number of loops; range/xrange needs to be one
      # more to get that count of loops.
      for x in range(0, retries + 1):
          try:
              local_path = key_local_path(obj, key.name, dest)
              if not path_check(local_path):
                 os.makedirs(local_path, mode=0744)

              if recurse:
                  local_file=os.path.join(local_path,os.path.basename(key.name))
              else:
                  local_file=os.path.join(dest)

              key.get_contents_to_filename(local_file)
              return_download_files.append({ 'obj': key.name, 'download': True, 'dest': local_file})
              download_keys = True

          except s3.provider.storage_copy_error as e:
              module.fail_json(msg= str(e))
          except SSLError as e:
              # actually fail on last pass through the loop.
              if x >= retries:
                  module.fail_json(msg="s3 download failed; %s" % e)
              # otherwise, try again, this may be a transient timeout.
              pass

    if download_keys and not next_download_s3file:
       module.exit_json(msg="GET operation complete", files=return_download_files, changed=True)
    elif not next_download_s3file:
       module.exit_json(msg="GET operation complete, no keys downloaded", changed=False)
    else:
        return return_download_files

def download_s3str(module, s3, bucket, obj, version=None):
    try:
        bucket = s3.lookup(bucket)
        key = bucket.get_key(obj, version_id=version)
        contents = key.get_contents_as_string()
        module.exit_json(msg="GET operation complete", contents=contents, changed=True)
    except s3.provider.storage_copy_error as e:
        module.fail_json(msg= str(e))

def get_download_url(module, s3, bucket, obj, expiry, changed=True, listFiles=None, next_download_url=False):
    if listFiles is None:
        listFiles = []



    try:
        bucket = s3.lookup(bucket)
        key = bucket.lookup(obj)
        url = key.generate_url(expiry)
        listFiles.append({ 'obj': obj, 'upload': False, 'url': url, 'expiry': expiry })
        if not next_download_url:

            module.exit_json(msg="Download url:", files=listFiles, changed=changed)
        else:

            return listFiles
    except s3.provider.storage_response_error as e:
        module.fail_json(msg= str(e))

def is_fakes3(s3_url):
    """ Return True if s3_url has scheme fakes3:// """
    if s3_url is not None:
        return urlparse.urlparse(s3_url).scheme in ('fakes3', 'fakes3s')
    else:
        return False

def is_walrus(s3_url):
    """ Return True if it's Walrus endpoint, not S3

    We assume anything other than *.amazonaws.com is Walrus"""
    if s3_url is not None:
        o = urlparse.urlparse(s3_url)
        return not o.hostname.endswith('amazonaws.com')
    else:
        return False

def get_resultset_onekey(s3, bucket, obj, version=None):
    bucket = s3.lookup(bucket)
    onekey = bucket.get_key(obj, version_id=version)
    return { 'results': [ onekey ] }

def key_local_path(obj, key_name, dest):

    if os.path.split(dest)[1] == '':
        key_path = os.path.dirname(key_name)
        key_path = key_path.replace(obj,'')

        key_path = os.path.join(dest,re.sub('^/(.*)', '\\1', key_path))
    else:
        key_path = os.path.dirname(dest)

    return key_path

def get_list_files(path, recurse=False):
    """ Return list files into path directory and subdirectories """
    fichiers=[]

    if recurse:
        for root, dirs, files in os.walk(path):
            for i in files:
                fichiers.append(os.path.join(root, i))
    else:
        fichiers.append(path)
    return fichiers

def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
            bucket         = dict(required=True),
            dest           = dict(default=None),
            encrypt        = dict(default=True, type='bool'),
            expiry         = dict(default=600, aliases=['expiration']),
            headers        = dict(type='dict'),
            marker         = dict(default=None),
            max_keys       = dict(default=DEFAULT_MAX_KEYS),
            metadata       = dict(type='dict'),
            mode           = dict(choices=['get', 'put', 'delete', 'create', 'geturl', 'getstr', 'delobj', 'list'], required=True),
            object         = dict(),
            permission     = dict(type='list', default=['private']),
            version        = dict(default=None),
            overwrite      = dict(aliases=['force'], default='always'),
            prefix         = dict(default=None),
            retries        = dict(aliases=['retry'], type='int', default=0),
            s3_url         = dict(aliases=['S3_URL']),
            src            = dict(),
            recurse        = dict(default=False, type='bool'),
        ),
    )
    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_BOTO:
        module.fail_json(msg='boto required for this module')


    bucket = module.params.get('bucket')
    encrypt = module.params.get('encrypt')
    expiry = int(module.params['expiry'])
    if module.params.get('dest'):
        dest = os.path.expanduser(module.params.get('dest'))
    headers = module.params.get('headers')
    marker = module.params.get('marker')
    max_keys = module.params.get('max_keys')
    metadata = module.params.get('metadata')
    mode = module.params.get('mode')
    obj = module.params.get('object')
    version = module.params.get('version')
    overwrite = module.params.get('overwrite')
    prefix = module.params.get('prefix')
    retries = module.params.get('retries')
    s3_url = module.params.get('s3_url')
    src = module.params.get('src')
    recurse = module.params.get('recurse')

    if recurse:
        if prefix is None:
            module.fail_json(msg ='Unknown prefix specifed to get, put, delobj recurse mode.')

    for acl in module.params.get('permission'):
        if acl not in CannedACLStrings:
            module.fail_json(msg='Unknown permission specified: %s' % str(acl))

    if overwrite not in ['always', 'never', 'different']:
        if module.boolean(overwrite):
            overwrite = 'always'
        else:
            overwrite = 'never'

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module)

    if region in ('us-east-1', '', None):
        # S3ism for the US Standard region
        location = Location.DEFAULT
    else:
        # Boto uses symbolic names for locations but region strings will
        # actually work fine for everything except us-east-1 (US Standard)
        location = region

    if module.params.get('object'):
        obj = os.path.expanduser(module.params['object'])

    # allow eucarc environment variables to be used if ansible vars aren't set
    if not s3_url and 'S3_URL' in os.environ:
        s3_url = os.environ['S3_URL']

    # bucket names with .'s in them need to use the calling_format option,
    # otherwise the connection will fail. See https://github.com/boto/boto/issues/2836
    # for more details.
    if '.' in bucket:
        aws_connect_kwargs['calling_format'] = OrdinaryCallingFormat()

    # Look at s3_url and tweak connection settings
    # if connecting to Walrus or fakes3
    try:
        if is_fakes3(s3_url):
            fakes3 = urlparse.urlparse(s3_url)
            s3 = S3Connection(
                is_secure=fakes3.scheme == 'fakes3s',
                host=fakes3.hostname,
                port=fakes3.port,
                calling_format=OrdinaryCallingFormat(),
                **aws_connect_kwargs
            )
        elif is_walrus(s3_url):
            walrus = urlparse.urlparse(s3_url).hostname
            s3 = boto.connect_walrus(walrus, **aws_connect_kwargs)
        else:
            aws_connect_kwargs['is_secure'] = True
            try:
                s3 = connect_to_aws(boto.s3, location, **aws_connect_kwargs)
            except AnsibleAWSError:
                # use this as fallback because connect_to_region seems to fail in boto + non 'classic' aws accounts in some cases
                s3 = boto.connect_s3(**aws_connect_kwargs)

    except boto.exception.NoAuthHandlerFound as e:
        module.fail_json(msg='No Authentication Handler found: %s ' % str(e))
    except Exception as e:
        module.fail_json(msg='Failed to connect to S3: %s' % str(e))

    if s3 is None: # this should never happen
        module.fail_json(msg ='Unknown error, failed to create s3 connection, no information from boto.')

    # If our mode is a GET operation (download), go through the procedure as appropriate ...
    if mode == 'get':
        if recurse:
            obj = prefix
            if not dest[-1:] == '/':
                dest += '/'

        # First, we check to see if the bucket exists, we get "bucket" returned.
        bucketrtn = bucket_check(module, s3, bucket)
        if bucketrtn is False:
            module.fail_json(msg="Source bucket cannot be found", failed=True)

        # Next, we check to see if the key in the bucket exists. If it exists, it also returns key_matches md5sum check.
        keyrtn = key_check(module, s3, bucket, obj, recurse, version=version, marker=marker, max_keys=max_keys)
        if keyrtn is False:
            if version is not None:
                module.fail_json(msg="Key %s with version id %s does not exist."% (obj, version), failed=True)
            else:
                module.fail_json(msg="Key %s does not exist."%obj, failed=True)


        download_files = None

        # If the destination path doesn't exist or overwrite is True, no need to do the md5um etag check, so just download.
        pathrtn = path_check(dest)
        if pathrtn is False or overwrite == 'always':
            download_files = download_s3file(module, s3, bucket, obj, recurse, dest, retries, version=version, marker=marker, max_keys=max_keys, return_download_files=download_files)

        # Compare the remote MD5 sum of the object with the local dest md5sum, if it already exists.
        if pathrtn is True:
            dict_md5_remote = keysum(module, s3, bucket, obj, recurse, version=version, marker=marker, max_keys=max_keys)

            idx_key = 0
            download_key = False

            for key_name, md5_remote in dict_md5_remote.iteritems():
                idx_key += 1
                local_dest = dest
                if os.path.isdir(local_dest):
                    local_dest = os.path.join(key_local_path(obj, key_name, local_dest), os.path.basename(key_name))

                md5_local = module.md5(local_dest)
                if idx_key < len(dict_md5_remote):
                    next_download_s3file = True
                else:
                    next_download_s3file = False

                if md5_local == md5_remote:
                    if overwrite == 'always':
                        download_files = download_s3file(module, s3, bucket, key_name, False, local_dest, retries, version=version, return_download_files=download_files, next_download_s3file=next_download_s3file)
                        download_key = True
                    else:
                        if download_files is None:
                            download_files = []
                        local_path = key_local_path(obj, key_name, local_dest)
                        if recurse:
                            local_file=os.path.join(local_path,os.path.basename(key_name))
                        else:
                            local_file=os.path.join(local_dest)
                        download_files.append({ 'obj': key_name, 'download': False, 'dest': local_file})

                        if not next_download_s3file and not download_key:
                            module.exit_json(msg="Local and remote object are identical, ignoring. Use overwrite=always parameter to force.", files=download_files, changed=False)
                else:
                    if overwrite in ('always', 'different'):
                        download_files = download_s3file(module, s3, bucket, key_name, False, local_dest, retries, version=version, return_download_files=download_files, next_download_s3file=next_download_s3file)
                        download_key = True
                    elif not next_download_s3file and not download_key:
                        module.exit_json(msg="WARNING: Checksums do not match. Use overwrite parameter to force download.")


    # if our mode is a PUT operation (upload), go through the procedure as appropriate ...
    if mode == 'put':

       # Use this snippet to debug through conditionals:
       # module.exit_json(msg="Bucket return %s"%bucketrtn)
       # sys.exit(0)
        if src is None:
            module.fail_json(msg="src parameter is required", failed=True)

        if recurse:
            obj = prefix
            if not os.path.isdir(src):
                module.fail_json(msg="Local object for PUT must be a folder for recurse mode", failed=True)
        elif not os.path.isfile(src):
            module.fail_json(msg="Local object for PUT must be a file for not recurse mode", failed=True)

        # Lets check the src path.
        pathrtn = path_check(src)
        if pathrtn is False:
            module.fail_json(msg="Local object for PUT does not exist", failed=True)

        # Lets check to see if bucket exists to get ground truth.
        bucketrtn = bucket_check(module, s3, bucket)
        if bucketrtn is True:
            keyrtn = key_check(module, s3, bucket, obj, recurse, version=version, marker=marker, max_keys=max_keys)

        # Lets check key state. Does it exist and if it does, compute the etag md5sum.
        if bucketrtn is True and keyrtn is True:

                listFiles = get_list_files(src, recurse)

                dict_md5_remote = keysum(module, s3, bucket, obj, recurse, version=version, marker=marker, max_keys=max_keys)
                idx_file = 0
                upload_files = None
                changed=False

                for file in listFiles:
                    idx_file += 1

                    md5_local = module.md5(file)
                    remote_file = file.replace(src,obj)
                    if dict_md5_remote.has_key(remote_file):
                        md5_remote = dict_md5_remote.get(remote_file)
                    else:
                        md5_remote = ''



                    if idx_file < len(listFiles):
                        next_upload_s3file = True
                    else:
                        next_upload_s3file = False

                    if md5_local == md5_remote:
                        if overwrite == 'always':
                            upload_files = upload_s3file(module, s3, bucket, remote_file, file, expiry, metadata, encrypt, headers, return_upload_files=upload_files, next_upload_s3file=next_upload_s3file)
                        else:
                            upload_files = get_download_url(module, s3, bucket, remote_file, expiry, changed=changed, listFiles=upload_files, next_download_url=next_upload_s3file)
                    else:
                        if overwrite in ('always', 'different'):
                            upload_files = upload_s3file(module, s3, bucket, remote_file, file, expiry, metadata, encrypt, headers, return_upload_files=upload_files, next_upload_s3file=next_upload_s3file)
                            changed=True
                        else:
                            module.exit_json(msg="WARNING: Checksums do not match. Use overwrite parameter to force upload.")


        # If neither exist (based on bucket existence), we can create both.
        if bucketrtn is False and pathrtn is True:
            create_bucket(module, s3, bucket, location)
            upload_s3file(module, s3, bucket, obj, src, expiry, metadata, encrypt, headers)

        # If bucket exists but key doesn't, just upload.
        if bucketrtn is True and pathrtn is True and keyrtn is False:
            putFiles = get_list_files(src, recurse)
            idx_file = 0
            upload_files = []

            for file in putFiles:
                idx_file +=1

                if idx_file < len(putFiles):
                    next_upload_s3file = True
                else:
                    next_upload_s3file = False

                remote_file = file.replace(src,obj)
                upload_files = upload_s3file(module, s3, bucket, remote_file, file, expiry, metadata, encrypt, headers, return_upload_files=upload_files, next_upload_s3file=next_upload_s3file)

    # Delete an object from a bucket, not the entire bucket
    if mode == 'delobj':
        if recurse:
            obj = prefix

        if obj is None:
            module.fail_json(msg="object parameter is required", failed=True);

        if bucket:
            bucketrtn = bucket_check(module, s3, bucket)
            if bucketrtn is True:
                delete_key(module, s3, bucket, obj, recurse=recurse, marker=marker, max_keys=max_keys)
            else:
                module.fail_json(msg="Bucket does not exist.", changed=False)
        else:
            module.fail_json(msg="Bucket parameter is required.", failed=True)


    # Delete an entire bucket, including all objects in the bucket
    if mode == 'delete':
        if bucket:
            bucketrtn = bucket_check(module, s3, bucket)
            if bucketrtn is True:
                deletertn = delete_bucket(module, s3, bucket)
                if deletertn is True:
                    module.exit_json(msg="Bucket %s and all keys have been deleted."%bucket, changed=True)
            else:
                module.fail_json(msg="Bucket does not exist.", changed=False)
        else:
            module.fail_json(msg="Bucket parameter is required.", failed=True)

    # Support for listing a set of keys
    if mode == 'list':
        bucket_object = get_bucket(module, s3, bucket)

        # If the bucket does not exist then bail out
        if bucket_object is None:
            module.fail_json(msg="Target bucket (%s) cannot be found"% bucket, failed=True)

        list_keys(module, bucket_object, prefix, marker, max_keys)

    # Need to research how to create directories without "populating" a key, so this should just do bucket creation for now.
    # WE SHOULD ENABLE SOME WAY OF CREATING AN EMPTY KEY TO CREATE "DIRECTORY" STRUCTURE, AWS CONSOLE DOES THIS.
    if mode == 'create':
        if bucket and not obj:
            bucketrtn = bucket_check(module, s3, bucket)
            if bucketrtn is True:
                module.exit_json(msg="Bucket already exists.", changed=False)
            else:
                module.exit_json(msg="Bucket created successfully", changed=create_bucket(module, s3, bucket, location))
        if bucket and obj:
            bucketrtn = bucket_check(module, s3, bucket)
            if obj.endswith('/'):
                dirobj = obj
            else:
                dirobj = obj + "/"
            if bucketrtn is True:
                keyrtn = key_check(module, s3, bucket, dirobj)
                if keyrtn is True:
                    module.exit_json(msg="Bucket %s and key %s already exists."% (bucket, obj), changed=False)
                else:
                    create_dirkey(module, s3, bucket, dirobj)
            if bucketrtn is False:
                created = create_bucket(module, s3, bucket, location)
                create_dirkey(module, s3, bucket, dirobj)

    # Support for grabbing the time-expired URL for an object in S3/Walrus.
    if mode == 'geturl':
        if bucket and obj:
            bucketrtn = bucket_check(module, s3, bucket)
            if bucketrtn is False:
                module.fail_json(msg="Bucket %s does not exist."%bucket, failed=True)
            else:
                keyrtn = key_check(module, s3, bucket, obj)
                if keyrtn is True:
                    get_download_url(module, s3, bucket, obj, expiry)
                else:
                    module.fail_json(msg="Key %s does not exist."%obj, failed=True)
        else:
            module.fail_json(msg="Bucket and Object parameters must be set", failed=True)

    if mode == 'getstr':
        if bucket and obj:
            bucketrtn = bucket_check(module, s3, bucket)
            if bucketrtn is False:
                module.fail_json(msg="Bucket %s does not exist."%bucket, failed=True)
            else:
                keyrtn = key_check(module, s3, bucket, obj, version=version)
                if keyrtn is True:
                    download_s3str(module, s3, bucket, obj, version=version)
                else:
                    if version is not None:
                        module.fail_json(msg="Key %s with version id %s does not exist."% (obj, version), failed=True)
                    else:
                        module.fail_json(msg="Key %s does not exist."%obj, failed=True)

    module.exit_json(failed=False)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

main()
