#!/usr/bin/env python3

import hashlib
import re
from vconnector.core import VConnector

from base64 import b64decode
from DPAPI import *
try:
    from Crypto import Random
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
except ImportError:
    from Cryptodome import Random
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import pad
from urllib.parse import unquote


class VMwarePref(object):

    # Public constants
    AES_IV_SIZE = AES.block_size
    AES_128_KEY_SIZE = 128 // 8
    AES_256_KEY_SIZE = 256 // 8
    IDENTIFIER_SIZE = 8
    SALT_SIZE = 8

    # Private constants
    __AES_MODE = AES.MODE_CBC
    __HASH_SIZE = 20  # sha1
    __DICT_SIZE = AES_IV_SIZE + 64 + __HASH_SIZE
    BASE64_RE = '([a-zA-Z0-9\+/=\/]+)'
    CIPHER_RE = '([A-Z0-9\-]+)'
    HASH_RE = '([A-Z0-9\-]+)'
    QUOTED_RE = '([a-zA-Z0-9\+/%/=]+)'
    ROUNDS_RE = '([0-9]+)'
    TYPE_RE = '([a-zA-Z]+)'
    ALL_CHAR = '([a-zA-Z0-9\\+\=\/()<>,-:\.@]+)'
    DATA_RE = '.*\"' + BASE64_RE + '\"'
    DATA2_RE = '.*\"' + ALL_CHAR + '\"'
    DATA3_RE = '\"' + BASE64_RE + '\"'
    DICT_RE = 'type=' + TYPE_RE \
              + ':cipher=' + CIPHER_RE \
              + ':key=' + QUOTED_RE
    ACE_DATA_RE = 'type=' + TYPE_RE \
                  + ':pass2key=' + HASH_RE \
                  + ':cipher=' + CIPHER_RE \
                  + ':rounds=' + ROUNDS_RE \
                  + ':salt=' + BASE64_RE \
                  + ':mac=' + HASH_RE \
                  + ':data=' + BASE64_RE
    KEYSAFE_RE = 'vmware:key\/list\/\(pair\/\(null\/<VMWARE-EMPTYSTRING>' \
                 + ',' + HASH_RE \
                 + ',' + BASE64_RE + '\)\)'
    PASSWORD_RE = ALL_CHAR + 'password = \"' + BASE64_RE + '\"'
    HOST_RE = ALL_CHAR + ' = \"' + ALL_CHAR + '\"'

    def __init__(self):
        """Initialize the public attributes

        Sets the public attributes to their default values
        """
        self.identifier = None
        self.salt = None
        self.aes_iv1 = None
        self.aes_iv2 = None
        self.aes_key1 = None
        self.aes_key2 = None
        self.hardcoded_password = "{23F781A1-4126-4bba-BC8A-9DD33D0E2362}"
        self.hardcoded_key = "oBQqVcdNH2NxXxP1O2nTrA=="

    @classmethod
    def new(cls):
        """Return a new class instance

        Returns:
            VMwarePref: the created class instance
        """
        return cls()

    def print_pref(self, pref):
        if pref:
            print("Credentials successfully decrypted:\n")
            for host in pref:
                    print("Hostname: " + host[0][0] + "\nUsername: " + host[0][1] + "\nPassword: " + host[0][2] + "\n")
        else:
            print("No credentials found!")

    def test_connection(self, pref):
        """
        Test the decrypted credentials
        :param pref: connection details
        :return: none
        """
        print("Testing credentials, please wait...\n")
        for host in pref:
            client = VConnector(
                host=host[0][0],
                user=host[0][1],
                pwd=host[0][2]
            )
            try:
                client.connect()
                print("Successfully connected to host: " + host[0][0] + " with user: " + host[0][1] +
                      " and password: " + host[0][2] + "\n")
                client.disconnect()
            except Exception as e:
                print("Cannot connect to host: " + host[0][0] + " with user: " + host[0][1] + " and password: "
                      + host[0][2] + "\nError: " + str(e) + "\n")
        print("Done!\n")

    def decrypt_dpapi(self, userKey):
        """
        Decrypt using DPAPI
        :param userKey: encryption.userKey value
        :return: decrypted data
        """
        return CryptUnprotectData(b64decode(userKey)).decode("utf-8")

    def aes_decrypt(self, enc, key):
        """
        Decrypot using AES algorithm
        :param enc: encrypted data
        :param key: secret key
        :return: decrypted data
        """
        dict_aes_iv = enc[:self.AES_IV_SIZE]
        cipher = AES.new(key, self.__AES_MODE, dict_aes_iv)
        dict_dec = cipher.decrypt(enc[self.AES_IV_SIZE:-self.__HASH_SIZE])
        del cipher
        # Get the last byte which contains the padding size
        # Layout of dict_dec: Decrypted Dictionary | Padding Bytes | Padding Size (1 byte)
        try:
            padding_size = ord(dict_dec[-1])  # Python 2
        except TypeError:
            padding_size = dict_dec[-1]  # Python 3

        # Check the padding size
        if padding_size < 1 or padding_size > 16:
            msg = 'Illegal dictionary padding value found: {}' \
                .format(padding_size)
            raise ValueError(msg)

        # Remove all padding bytes (between 1 and 16)
        dict_dec = dict_dec[:-padding_size]
        try:
            return dict_dec.decode("utf-8")
        except:
            return dict_dec

    def decode_base64(self, string):
        """Decode a BASE64 string

        Args:
            string (str): the BASE64 string to be decoded

        Returns:
            bytes: the decoded string or None if the string is invalid.
        """
        try:
            return bytes(b64decode(string))
        except (TypeError, ValueError):
            return None

    def decrypt_ace(self, ace_data_s):
        # Unquote, analyze and decrypt data line in ace.dat file
        ace_data_s = unquote(ace_data_s)
        match = re.match(self.DATA_RE, ace_data_s)
        if not match:
            msg = 'Unsupported format of the data line in the ace.dat file:\n' \
                  + ace_data_s
            raise ValueError(msg)
        ace_data_s = match.group(1)
        match = re.match(self.BASE64_RE, ace_data_s)
        if not match:
            msg = 'Unsupported format of the data line in the ace.dat file:\n' \
                  + ace_data_s
            raise ValueError(msg)
        ace_key = self.decode_base64(self.hardcoded_key)
        ace_data_s = self.decode_base64(ace_data_s)
        ace_data_decrypted_s = self.aes_decrypt(ace_data_s, ace_key)
        ace_data_decrypted_s = unquote(ace_data_decrypted_s)
        return ace_data_decrypted_s

    def decrypt_ace_data(self, ace_data_decrypted_s):
        # Analyze decrypted data line from ace.dat file and decrypt data content
        match = re.match(self.ACE_DATA_RE, ace_data_decrypted_s)
        if not match:
            msg = 'Unsupported format of the data content extracted from decrypted data line from the ace.dat file:\n' \
                  + ace_data_decrypted_s
            raise ValueError(msg)

        # Only one hash algorithm for the password is supported
        password_hash_s = match.group(2)
        if password_hash_s != 'PBKDF2-HMAC-SHA-1':
            msg = 'Unsupported password hash algorithm: ' + password_hash_s
            raise ValueError(msg)

        # Only one encryption algorithm for the dictionary is supported
        dict_cipher_s = match.group(3)
        if dict_cipher_s != 'AES-128':
            msg = 'Unsupported dictionary encryption algorithm: ' \
                  + dict_cipher_s
            raise ValueError(msg)

        # Get and check if the hash rounds are greater than 0
        hash_rounds = int(match.group(4))
        if hash_rounds == 0:
            msg = 'Password hash rounds must be non-zero'
            raise ValueError(msg)

        # Get, unquote and decode the password salt
        salt_s = match.group(5)
        salt = self.decode_base64(salt_s)
        if salt is None:
            msg = 'Password salt is not a valid BASE64 string: ' + salt_s
            raise ValueError(msg)

        # The password salt must have the right size else something is wrong
        if len(salt) != self.SALT_SIZE:
            msg = 'Password salt has incorrect length: {}'.format(len(salt))
            raise ValueError(msg)

        # Only one hash algorithm for the configuration is supported
        config_hash_s = match.group(6)
        if config_hash_s != 'HMAC-SHA-1':
            msg = 'Unsupported configuration hash algorithm: ' \
                  + config_hash_s
            raise ValueError(msg)

        # Get and decode the dictionary
        dict_s = match.group(7)
        ace_dict_enc = self.decode_base64(dict_s)
        if ace_dict_enc is None:
            msg = 'Dictionary is not a valid BASE64 string:\n' + dict_s
            raise ValueError(msg)

        # The dictionary must have the right size else something is wrong
        if len(ace_dict_enc) != self.__DICT_SIZE:
            msg = 'Dictionary has incorrect length: {}'.format(len(ace_dict_enc))
            raise ValueError(msg)

        # Create the dictionary AES Key with PBKDF2-HMAC-SHA-1
        dict_key = hashlib.pbkdf2_hmac('sha1', self.hardcoded_password.encode(), salt,
                                       hash_rounds, self.AES_128_KEY_SIZE)

        # Check if the result is an AES-128 key
        if len(dict_key) != self.AES_128_KEY_SIZE:
            msg = 'Dictionary AES key has incorrect length: {}' \
                .format(len(dict_key))
            raise ValueError(msg)

        # Decrypt the data
        ace_data_data_decrypted_s = self.aes_decrypt(ace_dict_enc, dict_key)

        # Analyze decrypted data data from ace.dat and extract key
        match = re.match(self.DICT_RE, ace_data_data_decrypted_s)
        if not match:
            msg = 'Unsupported format of the data data decrypted content extracted from decrypted data line from \
                            the ace.dat file:\n' \
                  + ace_data_data_decrypted_s
            raise ValueError(msg)
        key3 = unquote(match.group(3))
        key3 = self.decode_base64(key3)

        return key3

    def decrypt_userkey(self, userkey_s):
        # Unquote, analyse and decrypt encryption.userKey line
        userkey_s = unquote(userkey_s)
        match = re.match(self.DATA_RE, userkey_s)
        if not match:
            msg = 'Unsupported format of the encryption.userKey line:\n' \
                  + userkey_s
            raise ValueError(msg)
        userkey_s = match.group(1)
        match = re.match(self.BASE64_RE, userkey_s)
        if not match:
            msg = 'Unsupported format of the encryption.userKey line:\n' \
                  + userkey_s
            raise ValueError(msg)
        decrypted_data = self.decrypt_dpapi(userkey_s)

        # Analyse decrypted userKey and extract AES_KEY
        match = re.match(self.DICT_RE, decrypted_data)
        if not match:
            msg = 'Unsupported format of the encryption.userKey decrypted data:\n' \
                  + decrypted_data
            raise ValueError(msg)
        key1 = match.group(3)
        key1 = unquote(key1)
        return key1

    def decrypt_keysafe(self, keysafe_s, key1):
        # Unquote, analyze and decrypt encryption.keySafe line
        keysafe_s = unquote(keysafe_s)
        match = re.match(self.DATA2_RE, keysafe_s)
        if not match:
            msg = 'Unsupported format of the encryption.keySafe line:\n' \
                  + keysafe_s
            raise ValueError(msg)
        keysafe_s = match.group(1)
        match = re.match(self.KEYSAFE_RE, keysafe_s)
        if not match:
            msg = 'Unsupported format of the encryption.keySafe line:\n' \
                  + keysafe_s
            raise ValueError(msg)
        keysafe_s = match.group(2)
        keysafe_s = self.decode_base64(keysafe_s)
        key1 = self.decode_base64(key1)
        decrypted_data = self.aes_decrypt(keysafe_s, key1)
        match = re.match(self.DICT_RE, decrypted_data)
        if not match:
            msg = 'Unsupported format of the encryption.keySafe decrypted data:\n' \
                  + decrypted_data
            raise ValueError(msg)
        key2 = match.group(3)
        key2 = unquote(key2)
        return key2

    def decrypt_data(self, data_s, key2):
        # Unquote, analyse and decrypt encryption.data line
        data_s = unquote(data_s)
        match = re.match(self.DATA_RE, data_s)
        if not match:
            msg = 'Unsupported format of the encryption.data line:\n' \
                  + data_s
            raise ValueError(msg)
        data_s = match.group(1)
        match = re.match(self.BASE64_RE, data_s)
        if not match:
            msg = 'Unsupported format of the encryption.data line:\n' \
                  + data_s
            raise ValueError(msg)
        key2 = self.decode_base64(key2)
        data_s = self.decode_base64(data_s)
        decrypted_data = self.aes_decrypt(data_s, key2)
        return decrypted_data

    def decrypt(self, ace_data_s, userkey_s, keysafe_s, data_s, config, testcreds):
        """
        Decrypt the configuration
        :param ace_data_s: ace file data
        :param userkey_s: encryption.userKey
        :param keysafe_s: encryption.keySafe
        :param data_s: encryption.data
        :param config: print config flag
        :param testcreds: test credentials flag
        :return: status
        """

        # Decrypt the ace file
        ace_data_decrypted_s = self.decrypt_ace(ace_data_s)

        # Decrypt the ace data value and extract the key
        key3 = self.decrypt_ace_data(ace_data_decrypted_s)

        # Decrypt encryption.userKey and extract the key
        key1 = self.decrypt_userkey(userkey_s)

        # Decrypt encryption.keySafe and extract the key
        key2 = self.decrypt_keysafe(keysafe_s, key1)

        # Decrypt encryption.data
        decrypted_data = self.decrypt_data(data_s, key2)

        # Decrypt password from decrypted data
        pref = []
        decrypted_data_l = decrypted_data.splitlines()
        linecount = 0
        configdata = ""
        for line in decrypted_data_l:
            linecount +=1
            if 'password' in line:
                password_enc = line
                match = re.match(self.PASSWORD_RE, password_enc)
                if not match:
                    msg = 'Unsupported format of the password line:\n' \
                          + password_enc
                    raise ValueError(msg)
                password_enc_s = match.group(2)
                password_enc_s = self.decode_base64(password_enc_s)
                decrypted_data_s = self.aes_decrypt(password_enc_s, key3)
                decrypted_data_s = decrypted_data_s[20:len(decrypted_data_s)]
                decrypted_data_s = (str(decrypted_data_s, 'utf-8', 'ignore').split('\x00', 1)[0])
                configdata += re.sub(self.DATA3_RE, "\"" + decrypted_data_s + "\"", password_enc) + "\n"
                host = [[re.match(self.HOST_RE, decrypted_data_l[linecount - 3]).group(2),
                         re.match(self.HOST_RE, decrypted_data_l[linecount - 2]).group(2), decrypted_data_s]]
                pref.append(host)

            else:
                configdata += line + "\n"

        self.print_pref(pref)

        if config:
            print("Decrypted configuration: \n\n" + configdata)
        if testcreds:
            self.test_connection(pref)

        return True

