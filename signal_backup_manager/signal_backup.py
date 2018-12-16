from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from datetime import datetime
from fs import open_fs

import sqlite3
import ctypes
import filetype

import signal_backup_manager.Backups_pb2 as Backups_pb2


class SignalBackup():

    def __init__(self, bkp_file, passphrase):

        self.ressource_folder = open_fs('osfs://.').makedir(
                                'Signal_Backup_Data_'
                                + datetime.now().strftime("%Y-%m-%d--%H-%M-%S")
                            )

        self.attachments_folder = self.ressource_folder.makedir(
                                                'attachments', recreate=True)

        self.avatars_folder = self.ressource_folder.makedir(
                                                'avatars', recreate=True)

        self.preference_file = self.ressource_folder.open('preferences', 'w')

        self.db_connection = sqlite3.connect(
                        self.ressource_folder.getospath('/').decode('utf-8')
                        + '/backup.db'
                        )

        self.db_cursor = self.db_connection.cursor()

        self.file = open(bkp_file, 'rb')

        self.iv, salt = self.__read_iv_and_salt()

        key = self.__derive_backup_key(passphrase, salt)

        self.cipher_key, self.mac_key = self.__derive_cipher_and_mac_keys(key)

        self.cipher_counter = int.from_bytes(self.iv[:4], byteorder='big')

        for frame in self.__get_backup_frames():

            if frame.HasField('version'):
                self.__handle_version(frame.version)

            if frame.HasField('statement'):
                self.__handle_statement(frame.statement)

            if frame.HasField('preference'):
                self.__handle_preference(frame.preference)

            if frame.HasField('attachment'):
                self.__handle_attachment(frame.attachment)

            if frame.HasField('avatar'):
                self.__handle_avatar(frame.avatar)

            if frame.HasField('end'):
                break

        self.db_connection.commit()

        self.file.close()

    def __read_iv_and_salt(self):

        header_length_bytes = self.file.read(4)
        header_length = int.from_bytes(header_length_bytes, byteorder='big')
        header_frame = self.file.read(header_length)

        frame = Backups_pb2.BackupFrame()
        frame.ParseFromString(header_frame)

        return frame.header.iv, frame.header.salt

    def __derive_backup_key(self, passphrase, salt):

        i = bytes(passphrase, encoding='utf-8')
        h = i

        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        digest.update(salt)

        for _ in range(250000):
            digest.update(h + i)
            h = digest.finalize()
            digest = hashes.Hash(hashes.SHA512(), backend=default_backend())

        return h[:32]

    def __derive_cipher_and_mac_keys(self, key):

        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=bytes('Backup Export', encoding='utf-8'),
            backend=default_backend()
        ).derive(key)

        return derived[0:32], derived[32:64]

    def __get_backup_frames(self):

        while True:

            frame_length = self.file.read(4)
            frame_length = int.from_bytes(frame_length, byteorder='big')
            frame_enc = self.file.read(frame_length - 10)
            frame_mac = self.file.read(10)

            plaintext = self.__decrypt_frame(frame_enc, frame_mac)

            frame = Backups_pb2.BackupFrame()
            frame.ParseFromString(plaintext)

            yield frame

    def __decrypt_frame(self, frame_enc, frame_mac, file=False):

        self.iv = (self.cipher_counter.to_bytes(length=4, byteorder='big')
                   + self.iv[4:])
        self.cipher_counter += 1

        mac = hmac.HMAC(
            self.mac_key,
            hashes.SHA256(),
            backend=default_backend()
        )
        if file:
            mac.update(self.iv)
        mac.update(frame_enc)
        mac = mac.finalize()

        if frame_mac != mac[:10]:
            raise ValueError('Invalid MAC')

        cipher = Cipher(
            algorithms.AES(self.cipher_key),
            modes.CTR(self.iv),
            backend=default_backend()
        ).decryptor()

        plaintext = cipher.update(frame_enc) + cipher.finalize()

        return plaintext

    def __handle_version(self, version):

        self.db_cursor.execute(
                            'PRAGMA user_version = {};'.format(version.version)
                            )

    def __handle_statement(self, statement):

        params = ()
        for param in statement.parameters:
            if param.HasField('stringParamter'):
                params += (param.stringParamter,)
            if param.HasField('doubleParameter'):
                params += (param.doubleParameter,)
            if param.HasField('integerParameter'):
                if param.integerParameter > 2 ** 63:
                    params += (ctypes.c_long(param.integerParameter).value,)
                else:
                    params += (param.integerParameter,)
            if param.HasField('blobParameter'):
                params += (param.blobParameter,)
            if param.HasField('nullparameter'):
                params += (param.nullparameter,)

        self.db_cursor.execute(statement.statement, params)

    def __handle_preference(self, preference):

        self.preference_file.write(str(preference) + '\n')

    def __handle_ressource(self, res):

        res_enc = self.file.read(res.length)
        res_mac = self.file.read(10)
        res_plaintext = self.__decrypt_frame(res_enc, res_mac, file=True)

        return res_plaintext

    def __handle_attachment(self, attachment):

        attachment_data = self.__handle_ressource(attachment)
        file_extension = filetype.guess_extension(attachment_data)
        file_name = str(attachment.attachmentId)
        if file_extension:
            file_name += '.' + file_extension
        with self.attachments_folder.open(file_name, 'wb') as f:
            f.write(attachment_data)

    def __handle_avatar(self, avatar):

        avatar_data = self.__handle_ressource(avatar)
        file_extension = filetype.guess_extension(avatar_data)
        file_name = avatar.name
        if file_extension:
            file_name += '.' + file_extension
        with self.avatars_folder.open(file_name, 'wb') as f:
            f.write(avatar_data)

    def __del__(self):

        self.preference_file.close()
        self.db_connection.close()
        self.ressource_folder.close()
