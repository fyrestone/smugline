#!/usr/bin/env python
"""smugline - command line tool for SmugMug

Usage:
  smugline.py upload <album_name> --api-key=<api_key> --oauth-secret=<oauth_secret>
                                  [--from=folder_name]
                                  [--media=(videos | images | all)]
  smugline.py download <album_name> --api-key=<api_key> --oauth-secret=<oauth_secret>
                                    [--to=folder_name]
                                    [--media=(videos | images | all)]
  smugline.py process <json_file> --api-key=<api_key> --oauth-secret=<oauth_secret>
                                  [--from=folder_name]
  smugline.py list --api-key=api_key --oauth-secret=oauth_secret
  smugline.py create <album_name> --api-key=api_key --oauth-secret=oauth_secret
                                  [--privacy=(unlisted | public)]
  smugline.py clear_duplicates <album_name> --api-key=<api_key> --oauth-secret=<oauth_secret>
  smugline.py (-h | --help)

Arguments:
  upload            uploads files to a smugmug album
  download          downloads an entire album into a folder
  process           processes a json file with upload directives
  list              list album names on smugmug
  create            create a new album
  clear_duplicates  finds duplicate images in album and deletes them

Options:
  --api-key=api_key       your smugmug api key
  --oauth-secret=oauth_secret
                          your smugmug api oauth secret
  --from=folder_name      folder to upload from [default: .]
  --media=(videos | images | all)
                          upload videos, images, or both [default: images]
  --privacy=(unlisted | public)
                          album privacy settings [default: unlisted]

"""

# pylint: disable=print-statement
# TODO: Solve duplicate album name problem.
# Currently, process album by name only apply to the first one.
from docopt import docopt
from smugpy import SmugMug
import hashlib
import os
import sys
import re
import json
import pprint
import requests
import functools
from itertools import groupby

__version__ = '0.5.1'

IMG_FILTER = re.compile(r'.+\.(jpg|png|jpeg|tif|tiff|gif)$', re.IGNORECASE)
VIDEO_FILTER = re.compile(r'.+\.(mov|mp4|avi|mts)$', re.IGNORECASE)
ALL_FILTER = re.compile('|'.join([IMG_FILTER.pattern, VIDEO_FILTER.pattern]),
                        re.IGNORECASE)

# Aliasing for differences in Python 2.x and 3.x
if sys.version_info < (3,):
    get_input = raw_input
else:
    get_input = input


def auto_retry(times=10):
    """
    An auto retry decorator, can be used as:

    @auto_retry
    def foo(param): pass

    @auto_retry()
    def foo(param): pass

    @auto_retry(10)
    def foo(param): pass

    These usages are identical.

    :param times: retry times
    :return: decorated function
    """
    import inspect

    args, varargs, keywords, defaults = inspect.getargspec(auto_retry)
    default_dict = dict(zip(reversed(args), reversed(defaults)))

    if callable(times):
        wrapper_func = times
        times = default_dict['times']
    else:
        wrapper_func = None

    def wrapper(func):
        @functools.wraps(func)
        def inner_wrapper(*args, **kwargs):
            for i in xrange(0, times - 1):
                try:
                    return func(*args, **kwargs)
                except Exception as ex:
                    print('auto retry %s %d ...' % (func.__name__, i + 1))
            else:
                return func(*args, **kwargs)

        return inner_wrapper

    return wrapper(wrapper_func) if wrapper_func else wrapper


class SmugLine(object):
    def __init__(self, api_key, oauth_secret):
        self.smugmug = self._login(api_key, oauth_secret, 'SmugLine')
        self.md5_sums = {}

    def _login(self, api_key, oauth_secret, app_name):
        # Step 1: get request token and authorization URL:
        (url, request_token) = self.smugmug_oauth_request_token(api_key, oauth_secret, app_name, 'Full', 'Modify')

        # Step 2: "visit" the authorization URL:
        self.user_authorize_at_smugmug(url)

        # Step 3: Upgrade the authorized request token into an access token
        access_token = self.smugmug_oauth_get_access_token(api_key, oauth_secret, app_name, request_token)

        # Step 3.5: You should save off the access_token so you can resume at
        # the following step from now on.  There is no need to jump through
        # the request token and authorization URL more than once.

        # Step 4 (and step 1 in the future): log in with the (saved) access
        # token to get an authorized connection to smugmug.com:

        smugmug = self.smugmug_oauth_use_access_token(api_key, oauth_secret, app_name, access_token)

        return smugmug

    # Request a "request token" from the smugmug servers for the given permissions.
    #
    # Return a pair (url, requestToken) that can be used to authorize this app to
    # access the account of whomever logs in at the URL.
    @staticmethod
    @auto_retry
    def smugmug_oauth_request_token(api_key, oauth_secret, app_name, access="Public", perm="Read"):
        smugmug = SmugMug(api_key=api_key, oauth_secret=oauth_secret, app_name=app_name)

        # Get a token that is short-lived (probably about 5 minutes) and can be used
        # only to setup authorization at SmugMug
        response = smugmug.auth_getRequestToken()

        # Get the URL that the user must visit to authorize this app (implicilty includes the request token in the URL)
        url = smugmug.authorize(access=access, perm=perm)

        return url, response['Auth']  # (should contain a 'Token')

    # "Visit" the URL (well, print the instructions the user should use to visit
    # the URL).  Once this is done the request token can be used to log in to
    # that user's account and get an "access token" for this app to use that
    # account.
    #
    # This implementation blocks until the user acknowledges that they've completed
    # the authorization at smugmug.com
    @staticmethod
    def user_authorize_at_smugmug(url):
        get_input("Please authorize app at %s\n\nPress Enter when complete.\n" % url)

    # Request an "access token" based on the given request token.  The request token
    # should be authorized at smugmug.com.
    #
    # Return the "access token" that encodes the user's identity and the secrets
    # that authorize this app to access that user's smugmug account.
    @staticmethod
    @auto_retry
    def smugmug_oauth_get_access_token(api_key, oauth_secret, app_name, request_token):
        # Use the request token to log in (which should be authorized now)
        smugmug = SmugMug(api_key=api_key, oauth_secret=oauth_secret,
                          oauth_token=request_token['Token']['id'],
                          oauth_token_secret=request_token['Token']['Secret'],
                          app_name=app_name)

        # The request token is good for 1 operation: to get an access token.
        response = smugmug.auth_getAccessToken()

        # The access token should be good until the user explicitly
        # disables it at smugmug.com in their settings panel.
        return response['Auth']

    # Log into smugmug.com with an authorized accessToken.  The accessToken includes
    # the user's identity and, effectively, a password to get this application into
    # the account.
    @staticmethod
    def smugmug_oauth_use_access_token(api_key, oauth_secret, app_name, access_token):
        # Use the access token to log in
        smugmug = SmugMug(api_key=api_key, oauth_secret=oauth_secret,
                          oauth_token=access_token['Token']['id'],
                          oauth_token_secret=access_token['Token']['Secret'],
                          app_name=app_name)
        return smugmug

    @staticmethod
    def get_filter(media_type='images'):
        if media_type == 'videos':
            return VIDEO_FILTER
        if media_type == 'images':
            return IMG_FILTER
        if media_type == 'all':
            return ALL_FILTER

    def upload_file(self, album, image):
        self.smugmug.images_upload(AlbumID=album['id'], **image)

    # source: http://stackoverflow.com/a/16696317/305019
    @staticmethod
    def download_file(url, folder, filename=None):
        local_filename = os.path.join(folder, filename or url.split('/')[-1])
        if os.path.exists(local_filename):
            print('{0} already exists...skipping'.format(local_filename))
            return
        r = requests.get(url, stream=True)
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:  # filter out keep-alive new chunks
                    f.write(chunk)
                    f.flush()
        return local_filename

    def upload_json(self, source_folder, json_file):
        images = json.load(open(json_file))

        # prepend folder
        for image in images:
            image['File'] = source_folder + image['File']

        # group by album
        groups = []
        images.sort(key=lambda x: x['AlbumName'])
        for k, g in groupby(images, key=lambda x: x['AlbumName']):
            groups.append(list(g))

        for group in groups:
            album_name = group[0]['AlbumName']
            album = self.get_or_create_album(album_name)
            self._upload(group, album_name, album)

    def upload_folder(self, source_folder, album_name, file_filter=IMG_FILTER):
        album = self.get_or_create_album(album_name)
        images = self.get_images_from_folder(source_folder, file_filter)
        self._upload(images, album_name, album)

    def download_album(self, album_name, dest_folder, file_filter=IMG_FILTER):
        album = self.get_album_by_name(album_name)
        if album is None:
            print('Album {0} not found'.format(album_name))
            return
        images = self._get_images_for_album(album, file_filter)
        self._download(images, dest_folder)

    def _upload(self, images, album_name, album):
        images = self._remove_duplicates(images, album)
        for image in images:
            print('uploading {0} -> {1}'.format(image, album_name))
            self.upload_file(album, image)

    def _download(self, images, dest_folder):
        for img in images:
            print('downloading {0} -> {1}'.format(img['FileName'], dest_folder))
            self.download_file(img['OriginalURL'], dest_folder, img['FileName'])

    @auto_retry
    def _get_remote_images(self, album, extras=None):
        remote_images = self.smugmug.images_get(
            AlbumID=album['id'],
            AlbumKey=album['Key'],
            Extras=extras)
        return remote_images

    def _get_md5_hashes_for_album(self, album):
        remote_images = self._get_remote_images(album, 'MD5Sum')
        md5_sums = [x['MD5Sum'] for x in remote_images['Album']['Images']]
        self.md5_sums[album['id']] = md5_sums
        return md5_sums

    def _get_images_for_album(self, album, file_filter=IMG_FILTER):
        extras = 'FileName,OriginalURL'
        images = self._get_remote_images(album, extras)['Album']['Images']

        for image in [img for img in images if file_filter.match(img['FileName'])]:
            yield image

    @staticmethod
    def _file_md5(filename, block_size=2**20):
        md5 = hashlib.md5()
        f = open(filename, 'rb')
        while True:
            data = f.read(block_size)
            if not data:
                break
            md5.update(data)
        return md5.hexdigest()

    def _include_file(self, f, md5_sums):
        try:
            if self._file_md5(f) in md5_sums:
                print('skipping {0} (duplicate)'.format(f))
                return False
            return True
        except IOError as err:
            errno, strerror = err
            print('I/O Error({0}): {1}...skipping'.format(errno, strerror))
            return False

    def _remove_duplicates(self, images, album):
        md5_sums = self._get_md5_hashes_for_album(album)
        return [x for x in images if self._include_file(x.get('File'), md5_sums)]

    def get_albums(self):
        albums = self.smugmug.albums_get()
        return albums

    def list_albums(self):
        print('available albums:')
        for album in self.get_albums()['Albums']:
            pprint.pprint(album)

    def get_or_create_album(self, album_name):
        album = self.get_album_by_name(album_name)
        if album:
            return album
        return self.create_album(album_name)

    def get_album_by_name(self, album_name):
        albums = self.get_albums()
        try:
            matches = [x for x in albums['Albums']
                       if x.get('Title').lower() == album_name.lower()]
            return matches[0]
        except:
            return None

    @staticmethod
    def _format_album_name(album_name):
        return album_name[0].upper() + album_name[1:]

    def get_album_info(self, album):
        return self.smugmug.albums_getInfo(AlbumID=album['id'], AlbumKey=album['Key'])

    def create_album(self, album_name, privacy='unlisted'):
        public = (privacy == 'public')
        album_name = self._format_album_name(album_name)
        album = self.smugmug.albums_create(Title=album_name, Public=public)
        album_info = self.get_album_info(album['Album'])
        print('{0} album {1} created. URL: {2}'.format(
            privacy,
            album_name,
            album_info['Album']['URL']))
        return album_info['Album']

    @staticmethod
    def get_images_from_folder(folder, img_filter=IMG_FILTER):
        matches = []
        for root, dirnames, filenames in os.walk(folder):
            matches.extend(
                {'File': os.path.join(root, name)} for name in filenames
                if img_filter.match(name))
        return matches

    @auto_retry
    def _delete_image(self, image):
        # image filename may contains non ascii character, format will cause traceback.
        # repr(filename) only contains ascii character, format will be ok.
        print('deleting image {0}'.format(repr(image['FileName'])))
        self.smugmug.images_delete(ImageID=image['id'])

    def clear_duplicates(self, album_name):
        # clear duplicates by filename, same behavior as Smugmug's "skip duplicates".
        # P.S. MD5Sum field is not available now.
        album = self.get_album_by_name(album_name)
        remote_images = self._get_remote_images(album, 'FileName')
        md5_sums = set()
        for image in remote_images['Album']['Images']:
            if image['FileName'] in md5_sums:
                self._delete_image(image)
            md5_sums.add(image['FileName'])


if __name__ == '__main__':
    arguments = docopt(__doc__, version='SmugLine 0.4')
    smugline = SmugLine(
        arguments['--api-key'],
        arguments['--oauth-secret'])
    if arguments['upload']:
        file_filter = smugline.get_filter(arguments['--media'])
        smugline.upload_folder(arguments['--from'],
                               arguments['<album_name>'],
                               file_filter)
    if arguments['download']:
        file_filter = smugline.get_filter(arguments['--media'])
        smugline.download_album(arguments['<album_name>'],
                                arguments['--to'],
                                file_filter)
    if arguments['process']:
        smugline.upload_json(arguments['--from'],
                             arguments['<json_file>'])
    if arguments['list']:
        smugline.list_albums()
    if arguments['create']:
        smugline.create_album(arguments['<album_name>'], arguments['--privacy'])
    if arguments['clear_duplicates']:
        smugline.clear_duplicates(arguments['<album_name>'])
